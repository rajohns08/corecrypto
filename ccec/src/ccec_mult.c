/* Copyright (c) (2010-2020) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"

#if !CCEC_VERIFY_ONLY

#define CCEC_MULT_DEBUG 0

// Configuration
#define EC_CURVE_SUPPORT_ONLY_A_MINUS_3

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define SCA_MASK_MSBIT (((cc_unit)1) << (SCA_MASK_BITSIZE - 1))

// Conditionally swap contents of two points in constant time.
#define cond_swap_points(_n_, ...) ccn_cond_swap(_n_ * 2, __VA_ARGS__)

/*!
 @function   XYCZadd_ws
 @abstract   (X,Y)-only co-Z addition with update

 @param      ws       Workspace for internal computations
                        To be cleaned up by the caller.
 @param      cp       Curve parameters.

 @param      P        Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P + Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for P'
 @result
            Given the twos points P and Q and a curve cp,
            Compute P' and P+Q where
            P' ~= P (same point in the equivalence class)
            P' and (P+Q) have the same Z coordinate
            Z coordinate omitted in output
 */
#define CCEC_XYCZadd_ws_WORKSPACE_N(n) (2 * (n))
static void XYCZadd_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *P, cc_unit *Q)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &P[0], *t2 = &P[n], *t3 = &Q[0], *t4 = &Q[n];
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);

    /*
       Algo 18
       modified to have input and output in same buffer
       use more RAM but less than XYCZaddC_ws so that it does not matter
       Cost: 2S + 4M + 7sub
    */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1); //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);     // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t3, t5); // X2.A=C
    cczp_mul_ws(ws, zp, t3, t1, t5); // X1.A=B
    cczp_sub_ws(ws, zp, t5, t4, t2); // Y2-Y1
    cczp_sqr_ws(ws, zp, t1, t5);     // (Y2-Y1)^2 = D
    cczp_sub_ws(ws, zp, t1, t1, t3); // D - B

    cczp_sub_ws(ws, zp, t1, t1, t6); // X3
    cczp_sub_ws(ws, zp, t6, t6, t3); // C - B
    cczp_mul_ws(ws, zp, t4, t2, t6); // Y1 (C - B)
    cczp_sub_ws(ws, zp, t2, t3, t1); // B - X3
    cczp_mul_ws(ws, zp, t2, t5, t2); // (Y2-Y1) (B - X3)
    cczp_sub_ws(ws, zp, t2, t2, t4); // (Y2-Y1)(B - X3) - Y1 (C - B)

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   XYCZaddC_ws
 @abstract   (X,Y)-only co-Z conjugate addition with update

 @param      ws       Workspace for internal computations
                        To be cleaned up by the caller.
 @param      cp       Curve parameters.

 @param      P        Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P+Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for (P-Q)
 @result
             Given the twos points P and Q and a curve cp,
             Compute P' and P+Q where
             P' ~= P (same point in the equivalence class)
             (P-Q) and (P+Q) have the same Z coordinate
             Z coordinate omitted in output
 */

#define CCEC_XYCZaddC_ws_WORKSPACE_N(n) (7 * (n))
static void XYCZaddC_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *P, cc_unit *Q)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &P[0], *t2 = &P[n], *t3 = &Q[0], *t4 = &Q[n];
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);
    cc_unit *t7 = CC_ALLOC_WS(ws, n);

    /*
     Algo 19
     Modified to have same input and output buffers
     Cost: 3S + 5M + 11add/sub
     */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1); //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);     // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t1, t5); // X1 * A = B
    cczp_mul_ws(ws, zp, t1, t3, t5); // X2 * A = C
    cczp_add_ws(ws, zp, t5, t4, t2); // Y2+Y1
    cczp_sub_ws(ws, zp, t4, t4, t2); // Y2-Y1
    cczp_sub_ws(ws, zp, t3, t1, t6); // C - B
    cczp_mul_ws(ws, zp, t7, t2, t3); // Y1 * (C-B)
    cczp_add_ws(ws, zp, t3, t1, t6); // C + B

    cczp_sqr_ws(ws, zp, t1, t4);     // (Y2-Y1)^2
    cczp_sub_ws(ws, zp, t1, t1, t3); // X3 = (Y2-Y1)^2 - (C+B)
    cczp_sub_ws(ws, zp, t2, t6, t1); // B - X3
    cczp_mul_ws(ws, zp, t2, t4, t2); // (Y2-Y1) * (B-X3)

    cczp_sub_ws(ws, zp, t2, t2, t7); // Y3 = (Y2-Y1)*(B-X3) - Y1*(C-B)
    cczp_sqr_ws(ws, zp, t4, t5);     // F = (Y2+Y1)^2
    cczp_sub_ws(ws, zp, t3, t4, t3); // X3' = F - (C+B)
    cczp_sub_ws(ws, zp, t4, t3, t6); // X3' - B
    cczp_mul_ws(ws, zp, t4, t4, t5); // (X3'-B) * (Y2+Y1)
    cczp_sub_ws(ws, zp, t4, t4, t7); // Y3' = (X3'-B)*(Y2+Y1) - Y1*(C-B)

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   XYCZdblJac_ws
 @abstract   Point Doubling in Jacobian with Co-Z output

 @param      ws        Workspace for internal computations
                       To be cleaned up by the caller.
 @param      cp        Curve parameters.
 @param      twoP      Output: X:Y Jacobian coordinate for 2P
 @param      P         Output: X:Y Jacobian coordinate for P'
 @param      p         Input: P in Jacobian coordinates
 @result
            Given a point P and a curve cp,
            Compute 2P and P' where
            P' ~= P (same point in the equivalence class)
            2P and P' have the same Z coordinate
            Z coordinate omitted in output
 */
#define CCEC_XYCZdblJac_ws_WORKSPACE_N(n) (3 * (n))
static void XYCZdblJac_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *twoP, cc_unit *P, ccec_const_projective_point_t p)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &twoP[0], *t2 = &twoP[n], *t3 = &P[0], *t4 = &P[n];
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);
    cc_unit *t7 = CC_ALLOC_WS(ws, n);

    /*
    Cost (a=-3)     : 6S + 2M + 12add/sub
    Cost (generic)  : 6S + 3M + 10add/sub
     */

    cczp_sqr_ws(ws, zp, t7, ccec_const_point_x(p, cp)); //  X1^2
    cczp_add_ws(ws, zp, t4, t7, t7);                    //  2*X1^2
    cczp_add_ws(ws, zp, t7, t7, t4);                    //  3*X1^2
    cczp_sqr_ws(ws, zp, t3, ccec_const_point_z(p, cp)); //  Z1^2
    cczp_sqr_ws(ws, zp, t3, t3);                        //  Z1^4

#ifdef EC_CURVE_SUPPORT_ONLY_A_MINUS_3
    cczp_add_ws(ws, zp, t5, t3, t3); //  2*Z1^4
    cczp_add_ws(ws, zp, t5, t5, t3); //  3*Z1^4
    cczp_sub_ws(ws, zp, t7, t7, t5); //  B = 3*X1^2 - 3.Z1^4
#else
    cczp_mul_ws(ws, zp, t5, ccec_cp_a(cp), t3); //  a.Z1^4
    cczp_add_ws(ws, zp, t7, t7, t5);            //  B = 3*X1^2 + a.Z1^4
#endif
    cczp_sqr_ws(ws, zp, t4, ccec_const_point_y(p, cp));     //  Y1^2
    cczp_add_ws(ws, zp, t4, t4, t4);                        //  2Y1^2
    cczp_add_ws(ws, zp, t5, t4, t4);                        //  4Y1^2
    cczp_mul_ws(ws, zp, t3, t5, ccec_const_point_x(p, cp)); //  A = 4Y1^2.X1
    cczp_sqr_ws(ws, zp, t6, t7);                            //  B^2

    cczp_sub_ws(ws, zp, t6, t6, t3); //  B^2 - A
    cczp_sub_ws(ws, zp, t1, t6, t3); //  X2 = B^2 - 2.A
    cczp_sub_ws(ws, zp, t6, t3, t1); //  A - X2

    cczp_mul_ws(ws, zp, t6, t6, t7); //  (A - X2)*B
    cczp_sqr_ws(ws, zp, t4, t4);     //  (2Y1^2)^2
    cczp_add_ws(ws, zp, t4, t4, t4); //  8.Y1^4 = Y1'
    cczp_sub_ws(ws, zp, t2, t6, t4); //  Y2 = (A - X2)*B - 8.Y1^4

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   XYCZrecoverCoeffJac
 @abstract   Recover Z and lambdaX, lambdaY coefficients for the result point
    if b=0 => R1 - R0 = -P
    if b=1 => R1 - R0 = P

 @param      ws         Workspace for internal computations
                          To be cleaned up by the caller.
 @param      cp         Curve parameters.
 @param      lambdaX    Output: Correcting coefficient for X
 @param      lambdaY    Output: Correcting coefficient for Y
 @param      Z          Output: Z coordinate
 @param      R0         Input: X:Y Jacobian coordinates for P
 @param      R1         Input: X:Y Jacobian coordinates for Q
 @param      Rb         Input: X:Y Jacobian coordinates for P or Q
 @param      p          Input: input point to the scalar multiplication
 @result
    {lambaX, lambdaY, Z} so that the result point is recovered from R0
    after the last iteration.
 */
#define CCEC_XYCZrecoverCoeffJac_WORKSPACE_N(n) (0)
static void XYCZrecoverCoeffJac(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                cc_unit *lambdaX,
                                cc_unit *lambdaY,
                                cc_unit *Z,
                                const cc_unit *R0,
                                const cc_unit *R1,
                                const cc_unit *Rb,
                                ccec_const_projective_point_t p)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_unit *t1 = lambdaX, *t2 = lambdaY, *t3 = Z;

    cczp_sub_ws(ws, zp, t3, R0, R1);                        // X_R0 - X_R1
    cczp_mul_ws(ws, zp, t3, &Rb[n], t3);                    // Yb * (X_R0-X_R1)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_x(p, cp), t3); // XP * Yb*(X_R0-X_R1)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_z(p, cp), t3); // ZP * XP*Yb*(X_R0-X_R1)

    cczp_mul_ws(ws, zp, t2, Rb, ccec_const_point_y(p, cp)); // Xb*YP
    cczp_sqr_ws(ws, zp, t1, t2);                            // (Xb*YP)^2
    cczp_mul_ws(ws, zp, t2, t2, t1);                        // (Xb*YP)^3

    // {T1,T2,T3}
}

// Requires the point s to have been generated by "ccec_projectify"
static int ccec_mult_edge_cases(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                ccec_projective_point_t r,
                                const cc_unit *d,
                                size_t dbitlen,
                                ccec_const_projective_point_t s)
{
    int status;
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));
    CC_DECL_BP_WS(ws, bp);
    cc_unit *dtmp = CC_ALLOC_WS(ws, n + 1);

    ccn_sub1(n, dtmp, cczp_prime(ccec_cp_zq(cp)), 1); // q-1

    // Scalar d must be <= q to
    // prevent intermediary results to be the point at infinity
    // corecrypto to take care to meet this requirement
    if ((dbitlen >= ccec_cp_order_bitlen(cp)) && (ccn_cmp(n, d, cczp_prime(ccec_cp_zq(cp))) > 0)) {
        // d > q
        status = -1; // error
    } else if (dbitlen < 1) {
        // d == 0
        ccn_clear(n, ccec_point_x(r, cp));
        ccn_clear(n, ccec_point_y(r, cp));
        ccn_clear(n, ccec_point_z(r, cp));
        status = 1; // done
    } else if (dbitlen == 1) {
        // If d=1 => r=s
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        status = 1; // done
    } else if ((dbitlen >= ccec_cp_order_bitlen(cp)) && (ccn_cmp(n, d, dtmp) == 0)) {
        // If d=(q-1) => r=-s
        // Case not handled by Montgomery Ladder because R1-R0 = s.
        // On the last iteration r=R0 => R1 is equal to infinity which is not supported
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_sub(n, ccec_point_y(r, cp), cczp_prime(zp), ccec_const_point_y(s, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        status = 1; // done
    } else {
        status = 0;
    }
    CC_FREE_BP_WS(ws, bp);
    return status;
}

/*!
 @function   ccec_mult_ws
 @abstract   Scalar multiplication on the curve cp

 @param      ws          Workspace for internal computations
                           To be cleaned up by the caller.
 @param      cp          Curve parameter
 @param      r           Output point d.s
 @param      d           Scalar of size ccec_cp_n(cp)+1 cc_units.
                           Required to verify d<=q where q is the order of the curve
 @param      dbitlen     Bit length of scalar d
 @param      s           Input point in Jacobian projective representation
 @result
 */
#define CCEC_MULT_WORKSPACE_SIZE(n) (16 * (n) + 2)
static int ccec_mult_ws(cc_ws_t ws,
                        ccec_const_cp_t cp,
                        ccec_projective_point_t r,
                        const cc_unit *d,
                        size_t dbitlen,
                        ccec_const_projective_point_t s)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    int status = ccec_mult_edge_cases(ws, cp, r, d, dbitlen, s);
    if (status > 0) {
        return 0;
    }
    CC_DECL_BP_WS(ws, bp);
    cc_unit *R0 = CC_ALLOC_WS(ws, 2 * n); // R0,R1,Rb are full points:
    cc_unit *R1 = CC_ALLOC_WS(ws, 2 * n); // X in [0..n-1] and Y in [n..2n-1]
    cc_unit *Rb = CC_ALLOC_WS(ws, 2 * n);

    // Core of the EC scalar multiplication
    cc_unit dbit = 0; // Bit of d at index i
    XYCZdblJac_ws(ws, cp, R1, R0, s);

    // Main loop
    // Assumes that MSB is set: d_dbitlen-1 is == 1
    // This algo does not read it to verify it is indeed one.
    for (size_t i = dbitlen - 2; i > 0; --i) {
        dbit ^= ccn_bit(d, i);
        // Use buffer copy instead of pointer handling to prevent cache attacks
        cond_swap_points(n, dbit, R0, R1);
        XYCZaddC_ws(ws, cp, R0, R1);
        XYCZadd_ws(ws, cp, R0, R1);
        // Per Montgomery Ladder:
        // Invariably, R1 - R0 = P at this point of the loop
        dbit = ccn_bit(d, i);
    }

    // Last iteration
    dbit ^= ccn_bit(d, 0);

    cond_swap_points(n, dbit, R0, R1);
    XYCZaddC_ws(ws, cp, R0, R1);

    // Save current Rb.
    ccn_set(2 * n, Rb, R1);

    // Restore dbit, R0, R1.
    dbit = ccn_bit(d, 0);
    cond_swap_points(n, dbit, R0, R1);

    // If d0 =      0           1
    //          R1-R0=-P     R1-R0=P
    // Therefore we can reconstruct the Z coordinate
    // To save an inversion and keep the result in Jacobian projective coordinates,
    //  we compute coefficient for X and Y.
    XYCZrecoverCoeffJac(ws, cp, ccec_point_x(r, cp), ccec_point_y(r, cp), ccec_point_z(r, cp), R0, R1, Rb, s);

    cond_swap_points(n, dbit, R0, R1);
    XYCZadd_ws(ws, cp, R0, R1);
    ccn_mux(n * 2, dbit, R0, R1, R0);

    // Apply coefficients to get final X,Y
    cczp_mul_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp), &R0[0]); // X0 * lambdaX
    cczp_mul_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp), &R0[n]); // Y0 * lambdaY

#if CCEC_MULT_DEBUG
    ccn_lprint(n, "Result X:", ccec_point_x(r, cp));
    ccn_lprint(n, "Result Y:", ccec_point_y(r, cp));
    ccn_lprint(n, "Result Z:", ccec_point_z(r, cp));
#endif
    CC_FREE_BP_WS(ws, bp);

    return 0;
}

// Requires the point s to have been generated by "ccec_projectify"
int ccec_mult(ccec_const_cp_t cp,
              ccec_projective_point_t R,
              const cc_unit *d,
              ccec_const_projective_point_t S,
              CC_UNUSED struct ccrng_state *rng)
{
    int status;
    cc_size n = ccec_cp_n(cp);
    size_t dbitlen = ccn_bitlen(n, d);

    // R and S must not overlap.
    cc_assert(R != S);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_MULT_WORKSPACE_SIZE(n));
    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *Q = (ccec_projective_point *)CC_ALLOC_WS(ws, (ccec_point_size_n(cp)) + 2);
    cc_unit *dtmp1 = (cc_unit *)Q;         // dtmp1[n+1], ok to overlap with Q
    cc_unit *dtmp2 = (cc_unit *)Q + n + 1; // dtmp2[n+1], ok to overlap with Q
    cc_assert(ccec_point_size_n(cp) >= 2 * n);

    // Manage edge cases
    status = ccec_mult_edge_cases(ws, cp, R, d, dbitlen, S);
    cc_require(status >= 0, errOut); // error
    if (status > 0) {
        status = 0; // done
        goto errOut;
    }

    // Scalar splitting
    // (d + q - 2*SCA_MASK_MSBIT) to avoid leaking the bit size of scalars
    size_t q_bitlen = ccec_cp_order_bitlen(cp);
    ccn_zero(n, dtmp2);
    ccn_set_bit(dtmp2, SCA_MASK_BITSIZE, 1);
    ccn_sub(n, dtmp1, cczp_prime(ccec_cp_zq(cp)), dtmp2);                       // q - 2*SCA_MASK_MSBIT, no carry
    dtmp2[n] = ccn_add(n, dtmp2, dtmp1, d);                                     // q + d - 2*SCA_MASK_MSBIT
    dtmp1[n] = dtmp2[n] + ccn_add(n, dtmp1, dtmp2, cczp_prime(ccec_cp_zq(cp))); // 2*q + d - 2*SCA_MASK_MSBIT

    // Choose dtmp1 or dtmp2, the one with the desired bitsize.
    // dtmp1 := MAX(dtmp1, dtmp2)
    ccn_mux(n + 1, ccn_bit(dtmp2, q_bitlen), dtmp1, dtmp2, dtmp1);
    cc_assert(ccn_bitlen(n + 1, dtmp1) == ccec_cp_order_bitlen(cp) + 1);

    // Now the mask
    cc_unit mask = 1;
    cc_unit b = 0;
    cc_assert(SCA_MASK_N == 1);
#if CCEC_MASKING
    if (rng) {
        status = ccn_random_bits(SCA_MASK_BITSIZE, &mask, rng);
        cc_require(status == 0, errOut);
    }
#endif
    mask |= SCA_MASK_MSBIT;

    // (d + q - 2*SCA_MASK_MSBIT) = a.mask + b
    // => a.mask + (b+2*SCA_MASK_MSBIT) = d + q
    status = ccn_div_euclid_ws(ws, n + 1, dtmp1, SCA_MASK_N, &b, n + 1, dtmp1, SCA_MASK_N, &mask);
    cc_require(status == 0, errOut);

    // a.S
    // We don't allow x coordinates = 0.
    cc_require_action(ccn_is_zero(n, ccec_point_x(S, cp)) == 0, errOut, status = CCERR_PARAMETER);
    dbitlen = ccn_bitlen(n + 1, dtmp1);
    status = ccec_mult_ws(ws, cp, Q, dtmp1, dbitlen, S);
    cc_require(status == 0, errOut);

    // mask.a.S
    // We don't allow x coordinates = 0.
    cc_require_action(ccn_is_zero(n, ccec_point_x(Q, cp)) == 0, errOut, status = CCERR_PARAMETER);
    dbitlen = SCA_MASK_BITSIZE;
    status = ccec_mult_ws(ws, cp, R, &mask, dbitlen, Q);
    cc_require(status == 0, errOut);

    // b.S
    dbitlen = SCA_MASK_BITSIZE + 1; // equivalent to b+(2*SCA_MASK_MSBIT)
    status = ccec_mult_ws(ws, cp, Q, &b, dbitlen, S);
    cc_require(status == 0, errOut);

    // mask.a.S + b.S
    ccec_add_ws(ws, cp, R, R, Q, 0); // If either point is infinity, result is infinity

    status = 0;
errOut:
    CC_FREE_BP_WS(ws, bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}

#endif  // !CCEC_VERIFY_ONLY
