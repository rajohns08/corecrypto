/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn.h>
#include "ccn_internal.h"
#include "cc_debug.h"
#define CC_DEBUG_MAKERECIP (CORECRYPTO_DEBUG && 0)

/* Calculate the reciprocal r of a number d.
 r becomes the steady-state reciprocal
 2^(2b)/d, where b = bit-length of d.
 d      is of size d_nunits
 recip  must be of size d_nunits+1

 Below a Newton-raphson method is used to find the big number reciprocal to a value d.
 That is we wish to compute (2^(2b)/d), where b is the number of bits in the big number representation of  d. See a standard big-numbers text for more.
 
 Further, to ensure side-channel resilience the algorithm is running in constant time in b. In order to accomplish this with Newton-Raphson techniques, we need to determine a good initial guess at the solution where we can bound the bits of precision, and then further bound how many bits of precision are "gained" in each iteration. Then assuming the worst-case, we know we have hit a steady-state when we have surpassed b bits of precision. The initial part of this code and comments show and establish these derivations.
 */

#define R0_PRECISION 4    /* Precision of the first approximation */
#define INIT_PRECISION 10 /* Precision of intermediate values for first approximation */
void ccn_make_recip_ws(cc_ws_t ws, cc_size d_nunits, cc_unit *recip, const cc_unit *d)
{
    cc_size b = ccn_bitlen(d_nunits, d);
    cc_size n = ccn_nof(b + 2); // 2^(b+1)
    // main logic requires b>=2, handle other cases as special
    // if b=0 => d = 0 => recip=0
    // if b=1 => d = 1 => recip=4
    if (b <= 1) {
        ccn_seti(d_nunits + 1, recip, b * 4);
        return;
    }

    // Working buffers
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *tmp1 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *tmpd = CC_ALLOC_WS(ws, n);
    cc_unit *tmpr = CC_ALLOC_WS(ws, n);
    cc_unit c1, c2;

    // Locals
    ccn_setn(n, tmpd, CC_MIN(d_nunits, n), d);

    // Newton-Raphson is typically defined in float numbers with 0.5 <= D <= 1
    // And provides a quadratic convergence with the recursion X_{i+1}=X_{i}(2-D.X_{i})
    // In this case we want r=2^(2b)/d, which can be expressed as a zero of f: X->2^(2b)/X-d.
    // Using the recursion X_{i+1} = X_i - f(X_i)/f'(X_i)
    // it becomes: X_{i+1} = X_i (2^(2b+1) - d.X_i^2)/2^(2b))
    
    // To speed up the execution, the initial value X_{0} is important.
    // We use a linear approximation of the division: r0 = T1*2^b + T2*d for some constants {T1,T2}.
    // T1 and T2 are chosen to minimize the error: Epsilon0(d) = 2^(2b) - d*r0 = 2^(2b) - d*(T1*2^b + T2*d) for any
    // d such that 2^(b-1) < d < 2^b.
    // Epsilon0(d) = 2^(2b) - T2*d^2 - (T1*2^b)*d, which has maximum for d=2^(b-1) and minimum for d=2^b
    // The local extremum is provided by Epsilon0'(d) = -2T2.d - T1.2^b == 0 reached with d = -T1*2^b/(2*T2)
    // Epsilon0(2^(b-1)) == Epsilon0(2^b) == -Epsilon0(-T1*2^b/(2*T2))
    // which has solution T1 = 48/17 and T2 = -32/17
    // The maximum precision we get out of r0 depends on the maximum Epsilon0:
    //     Epsilon0(d) <= Epsilon0(2^b-1)
    //     Epsilon0(d) <= 2^(2b) * 1/17 (~4bits of precision)
    
    // In practice, we have rounding occuring in the computation of r0
    // We denote below r0ideal = 48/17*2^b - 32/17*d
    // and we evaluate how the compute r0 may differ from r0ideal
    const cc_unit t2 = ((32 << INIT_PRECISION) + 16) / 17;    // 32*2^p/17      < t2 < 32*2^p/17 + 1
    if (b >= 2 * INIT_PRECISION) {
        const cc_unit t1 = (48 << (2 * INIT_PRECISION)) / 17; // 48*2^2p/17 - 1 < t1 < 48*2^2p/17
        cc_assert(2 * INIT_PRECISION + 3 <= CCN_UNIT_BITS);
        ccn_shift_right_multi(n, tmp1, tmpd, (b - INIT_PRECISION)); // d/2^(b-p) - 1 < MS_p_bits(d) < d/2^(b-p)
        tmp1[0] =
            t1 - (t2 * (tmp1[0] + 1));
        // 32*2^p/17 * (MS_p_bits(d)+1) < t2 * (MS_p_bits(d)+1) < (32*2^p/17 + 1) * (MS_p_bits(d)+1)
        // 32*2^p/17 * (d/2^(b-p)) < t2 * (MS_p_bits(d)+1) < (32*2^p/17 + 1) * (d/2^(b-p)+1)
        // 48*2^2p/17 - 1 - (32*2^p/17+1) * (d/2^(b-p)+1) < t1 - t2 * (MS_p_bits(d)+1) < 48*2^2p/17 - 32*2^p/17 * (d/2^(b-p))
        // r0ideal*2^(2p-b) - 2 - 32*2^p/17 - 2^p*d/2^b < t1 - t2 * (MS_p_bits(d)+1) < r0ideal*2^(2p-b)
        // r0ideal - (2 + 2^p*32/17 + 2^p*d/2^b)*2^(b-2p) < (t1 - t2 * (MS_p_bits(d)+1))*2^(b-2p) < r0ideal
        //  2^(2b) - d*r0ideal < 2^(2b) -d*r0 < 2^(2b)-d*(r0ideal - (2 + 2^p*32/17 + 2^p*d/2^b)*2^(b-2p))
        //  Espilon0 < 2^(2b) -d*r0 < Espilon0 + d*(2 + 2^p*32/17 + 2^p*d/2^b)*2^(b-2p)
        //  With d<2^b => Espilon0 < 2^(2b) -d*r0 < Espilon0 + 2^(2b)*(2 + 2^p*49/17)/2^(2p)
        
        // To have R0_PRECISION bit precision:  (1/17 + (2 + 2^p*49/17)/2^(2p)) < 1/2^R0_PRECISION
        // Therefore we choose INIT_PRECISION = 10 for R0_PRECISION=4bit precision
        cc_assert((34+(1<<INIT_PRECISION)*49*(1<<R0_PRECISION) < (17-(1<<R0_PRECISION))*(1<<(2*INIT_PRECISION))));
        ccn_shift_left_multi(n, tmpr, tmp1, (b - 2 * INIT_PRECISION));
    } else {
        const cc_unit t1 = (48 << (INIT_PRECISION)) / 17;           // 48*2^p/17 - 1 < t1 < 48*2^p/17
        cc_assert(INIT_PRECISION + 3 + b <= CCN_UNIT_BITS);
        
        // - 32*2^p*d/17 - 1 < - t2*d < - 32*2^p*d/17
        // 48*2^b*2^p/17 - 2^b - 1 - 32*2^p*d/17 < tmpr < 48*2^b*2^p/17 - 32*2^p*d/17
        // r0ideal - (2^b+1)/2^p - 1 < r0 < r0ideal
        // Espilon0 < Espilon0 + d*((2^b+1)/2^p + 1)
        // For b>8 (1/17 + ((2^b+1)/2^p + 1)/2^b) < (1/17 + (1/2^p + 1/2^(p+b) + 1/2^b) < 1/2^R0_PRECISION
        // For b>3 (1/17 + ((2^b+1)/2^p + 1)/2^b) < 1/2^(R0_PRECISION-1)
        // For b=3 (1/17 + ((2^b+1)/2^p + 1)/2^b) < 1/2^(R0_PRECISION-2)
        // For b=2 (1/17 + ((2^b+1)/2^p + 1)/2^b) < 1/2^(R0_PRECISION-3)
        tmpr[0] = (t1 << b) - (t2 * tmpd[0]);
        tmpr[0] >>= INIT_PRECISION;
    }
    // c = ceiling((b+1)/R0_PRECISION)
    // S = ceiling(Log2(c1))
    // With exact operations, the convergence is
    //      EpsilonExact_i = 2^(2b) - d.X_{i}
    //      EpsilonExact_i = (EpsilonExact_(i-1)/2^b)^2
    // Hence: EpsilonExact_S-1 = (EpsilonExact_0^(2^S) / 2^(b*2*(2^S-1)))
    //      S=Log2(c) and Espilon0 < 2^(2b-R0_PRECISION)
    //          => EpsilonExact_S-1 < (2^(2b-R0_PRECISION)^(c) / 2^(b*2*(c-1)))
    //          => EpsilonExact_S-1 < 2^(2b-c*R0_PRECISION)
    //          => EpsilonExact_S-1 < 2^(b-1) < d with c = (b+1)/R0_PRECISION
    
    // The convergence is not exactly quadratic because of rounding on every iteration
    //      X_i - 2 < r_i < X_i
    //      Epsilon_i = (Epsilon_(i-1)/2^b)^2 + 2d
    // It varies from the exact epsilon after the ith iteration by:
    //      Epsilon_i = EpsilonExact_i + (2i)*d
    // This can be proven as follows:
    //      Epsilon_i+1 = (EpsilonExact_i + (2i)*d)^2/2^(2b) + 2*d
    //      Epsilon_i+1 = (EpsilonExact_i^2 + 2*(2i)*d*EpsilonExact_i + (2i)^2*d^2)/2^(2b) + 2*d
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*2^(b-3) + (i+2)^2 + 2*d with EpsilonExact_i < 2^(2b-2)
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*(2^(b-3) + i/2 + 3) + 2*d   with  (i+2)^2/(2i) < (i/2 + 3)
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*(2^(b-3) + (b+1)/8 + 3) + 2*d with i+1 < 2^i <= 2^(S-1) < (b+1)/4
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*(2^(b-3) + (2^b)/8 + 3) + 2*d with log(x)+1 <= x
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*(2^(b-2) + 2) + 2*d with 2^(b-2) + 3 <= 2^(b-1) if b>=4
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + (2i)*d + 2*d with 2^(b-1) <= d
    //      Epsilon_i+1 = EpsilonExact_{i+1}^2 + 2*(i+1)*d
    //      We want to find S'= log2(c') such that
    //                          Epsilon_{S'-2} < EpsilonExact_{S'-2} + 2*(S'-2)*d < 2^(3/2*b-1/2)
    //                          2^(2b-(c'/2)*R0_PRECISION) < 2^(3/2*b-1/2) - 2*(log2(c')-2)*d
    //          By looking at the function F with c' >= 1 + 1/2*(b+1)/R0_PRECISION
    //                  F:b -> 2^(3/2*b-1/2) - 2^(2b-(c')*R0_PRECISION) - 2*(log2(c')-1)*d
    //             we show that F(b)>0 for all b>=0 (the function can be plotted for quick verification)
    //          therefore Epsilon_{S'-2} < 2^(3/2*b-1/2)
    //          hence Epsilon_{S-1} < 2^(b-1) + 2d

    cc_unit cprime = 1 + cc_ceiling(b + 1,(2*R0_PRECISION));
    size_t S = 1+ccn_bitlen(1, &cprime);
    cc_size shift_nunits = b / CCN_UNIT_BITS;
    size_t shift_nbits = b - shift_nunits * CCN_UNIT_BITS;
    for (size_t i = 0; i < S; i++) {
        size_t k = CC_MIN((b + 1), 1 + R0_PRECISION * (((size_t)1) << (i + 1)));
        cc_size ignore_nunits = ((b + 1) - k) / CCN_UNIT_BITS;

        ccn_zero(ignore_nunits, tmpr);                 // ignored in this loop
        ccn_zero(ignore_nunits, tmp1 + ignore_nunits); // ignore_nunits*CCN_UNIT_BITS <b so we don't
                                                       // need to clear the bottom part
#if CC_DEBUG_MAKERECIP
        printf("R%zu: {%zu,%zu} ", i, k, ignore_nunits);
        ccn_lprint(n, "R:", tmpr);
#endif
        
        ccn_sqr_ws(ws, n - ignore_nunits, tmp1 + 2 * ignore_nunits, tmpr + ignore_nunits); // r^2
        ccn_shift_right(2 * n, tmp1, tmp1, shift_nbits); // r^2/2^b - 1 < tmp1 <= r^2/2^b
        ccn_add1(n, tmp2, tmp1 + shift_nunits, 1);       // r^2/2^b < tmp2 < r^2/2^b + 1
        ccn_mul_ws(
            ws, n, tmp1, tmpd, tmp2); // d*(r^2/2^b) < tmp1 <= d*(r^2/2^b + 1)
        ccn_shift_right(2 * n, tmp1, tmp1, shift_nbits); // d*(r^2/2^(2b)) - 1 < tmp1 <= d*(r^2/2^b + 1)/2^b
        ccn_add1(n, tmp2, tmp1 + shift_nunits, 1); // d*(r^2/2^(2b)) < tmp1 <= d*(r^2/2^b + 1)/2^b + 1
        ccn_shift_left(n, tmpr, tmpr, 1);          // 2*r
        ccn_sub(n, tmpr, tmpr, tmp2); // 2*r - d*(r^2/2^(2b)) - d/2^b - 1 < tmpr <= 2r - d*(r^2/2^(2b))
    }

#if CC_DEBUG_MAKERECIP
    ccn_lprint(n, "Re:", tmpr);
#endif
    // The error coming out of the last iteration is <3d
    ccn_zero(2 * n, tmp1);
    ccn_set_bit(tmp1, 2 * b, 1); // tmp1 = 2^(2b)
    ccn_mul_ws(ws, n, tmp2, tmpr, tmpd);
    ccn_sub(2 * n, tmp1, tmp1, tmp2);
    c1 = ccn_subn(2 * n, tmp1, tmp1, n, tmpd);
    c2 = ccn_subn(2 * n, tmp1, tmp1, n, tmpd);
    ccn_add1(n, tmpr, tmpr, (1 - c1) + ((1 - c2) & (1 - c1)));
#if CC_DEBUG_MAKERECIP
    ccn_lprint(n, "Rf:", tmpr);
#endif
    if (!(c1 | c2 | ccn_subn(2 * n, tmp1, tmp1, n, tmpd))) {
    // If any of the borrow is not set, the work is not down.
#if CORECRYPTO_DEBUG
        ccn_lprint(n, "ABORT d:", tmpd);
#endif
        cc_try_abort("internal error, file radar to (corecrypto | all)");
    }
    ccn_setn(d_nunits + 1, recip, n, tmpr);
    CC_FREE_BP_WS(ws, bp);
}

int ccn_make_recip(cc_size d_nunits, cc_unit *recip, const cc_unit *d)
{
    ccn_zero(d_nunits + 1, recip); // If workspace fails, recip is all zeroes
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_MAKE_RECIP_WORKSPACE_SIZE(d_nunits));
    ccn_make_recip_ws(ws, d_nunits, recip, d);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}
