/* Copyright (c) (2011,2012,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>
#include "ccn_internal.h"
#include "cc_debug.h"
#include "cc_memory.h"

/* Computes q = a / d and r = a%d
 -q can be NULL
 -r can be NULL
 -writes nq and nr items to q and r respectively, adding leading zeros if needed
 -reads na from a and rd from d.
 -execution time depends on the size of a
 */

int ccn_div_euclid(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d)
{
    int status;
    CC_DECL_WORKSPACE_OR_FAIL(ws,CCN_DIV_EUCLID_WORKSPACE_SIZE(na,nd));
    status = ccn_div_euclid_ws(ws,nq,q,nr,r,na,a,nd,d);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}

int ccn_div_euclid_ws(cc_ws_t ws, cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d)
{
    int status;
    CC_DECL_BP_WS(ws,bp);
    cc_unit *recip_d = CC_ALLOC_WS(ws,nd+1);
    ccn_make_recip_ws(ws,nd, recip_d, d);
    status = ccn_div_use_recip_ws(ws, nq, q, nr, r, na, a, nd, d, recip_d);
    CC_FREE_BP_WS(ws,bp);
    return status;
}

// Small integers and their reciprocal as returned by ccn_make_recip():  (d, recip_d) (1, 3) (2, 7) (3, 5) (4, 15)
// The execution time depends on the operand size but not their value
// Error case may have different execution time.
int ccn_div_use_recip_ws(cc_ws_t ws, cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d, const cc_unit *recip_d)
{
    size_t recip_bitlen = ccn_bitlen(1 + nd, recip_d);
    size_t d_bitlen = ccn_bitlen(nd, d);
    size_t nd_actual = ccn_n(nd, d);

    //if divisor is zero or reciprocal is missing return error
    if(d_bitlen==0 || recip_bitlen==0) return -2;

    if (r && nr < nd) {
        return CCERR_PARAMETER;
    }

    // the reciprocal must be one bit longer, up to 2 bits when d is a power of 2
    cc_assert((d_bitlen == recip_bitlen -1) || (d_bitlen == recip_bitlen -2));

    cc_size n = CC_MAX(2*nd,na);

    // each loop iteration reduces the number by 2^(bitlen-2)
    // because the substraction on the loop does a-d*q where q <= 3+a/d
    // therefore we deal with up to bitlen-2 bits at each iteration (see math below)
    size_t loop_iterations;

    if (d_bitlen>2) {
        loop_iterations=((ccn_bitsof_n(n)-1)/(d_bitlen-2));
    } else { // case where s=2, divisor d equals to one. The division loop reduces at least one bit per iteration (very slow case)
        loop_iterations=(ccn_bitsof_n(n)-2);
    }

    // Working buffers
    //      total is 2*n + n+3 + 1+n + n + n + na = 6*CC_MAX(2*nd,na) + 4 + na
    CC_DECL_BP_WS(ws,bp);
    cc_unit *t1 = CC_ALLOC_WS(ws,2*(n-nd_actual+1)); /* t1[2*(n-nd_actual+1)] */
    cc_unit *t2 = CC_ALLOC_WS(ws,3+n); /* t2[3+n] */
    cc_unit *d1 = CC_ALLOC_WS(ws,1+CC_MAX(nd,n-nd_actual));  /* d1[1+CC_MAX(nd,n-nd_actual)] */
    cc_unit *recip1 = CC_ALLOC_WS(ws,n); /* recip1[n] */
    cc_unit *a1 = CC_ALLOC_WS(ws,n); /* a1[n] */
    cc_unit *q1 = CC_ALLOC_WS(ws,na);   /* q1[na] */

    if (n>2+2*nd) {
        ccn_zero(n-(2+2*nd),&t2[2+2*nd]);
    }

    // Set loop initial values
    ccn_setn(n, recip1, nd+1, recip_d);
    ccn_setn(CC_MAX(nd+1,n-nd_actual+1), d1, nd, d);
    ccn_setn(n, a1, na, a);
    ccn_zero(na, q1);

    // Main loop to build an approximation
    cc_size n1=n;
    for (size_t k=0; k<loop_iterations; k++) {

        // q = (a / 2^(s-1) * (2^(2s)/d)) / 2^(s+1) is an approximation of the quotient a/d
        //Error is a/d - q <= 3. We adjust after the loop.
        ccn_shift_right_multi(n1, t2, a1, d_bitlen-1);    // a / 2^(s-1)
        ccn_mul(n1-nd_actual+1, t1, recip1, t2);            // * (2^(2s)/d)
        ccn_shift_right_multi(n1+1, t2, t1, d_bitlen+1);  // / 2^(s+1)
        ccn_add(na,q1,q1,t2);                               // quotient

        //compute the remainder
        ccn_mul(n1-nd_actual+1, t1, d1, t2);                // * d
        ccn_sub(n1, a1, a1, t1);                            // remainder

        n1 = CC_MAX(2*nd, n1-nd_actual+1); // adjust n for performance
    }

    // First conditional subtraction (0 <= r < 3d).
    cc_unit b = ccn_sub(1 + nd, t1, a1, d1);
    ccn_mux(1 + nd, b, a1, a1, t1);
    ccn_add1(na, q1, q1, b ^ 1);

    // Second conditional subtraction (0 <= r < 2d).
    b = ccn_sub(1 + nd, t1, a1, d1);
    ccn_mux(nd, b, a1, a1, t1);
    ccn_add1(na, q1, q1, b ^ 1);

    // 0 <= r < d.
    cc_assert(ccn_cmp(n, a1, d1) < 0);

    if (r) { // Remainder requested by caller.
        ccn_setn(nr, r, nd, a1);
    }

    if (q) { // Quotient is requested by caller
        cc_assert(nq >= ccn_n(na, q1));

        if (nq >= na) {
            ccn_setn(nq, q, na, q1);
        } else {
            ccn_set(nq, q, q1);
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}
