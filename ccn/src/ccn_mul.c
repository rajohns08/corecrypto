/* Copyright (c) (2010-2012,2014-2020) Apple Inc. All rights reserved.
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

// Number of cc_unit under which regular schoolbook multiplication is applied.
#define CCN_MUL_KARATSUBA_THRESHOLD 10

#if CCN_MUL_KARATSUBA
// Karatsuba.
// Recursive but the recursion depth is low < log2(n)
// Use the workspace for memory. Confined with 4*n.
void ccn_mul_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    CC_DECL_BP_WS(ws,bp);
    if (n<CCN_MUL_KARATSUBA_THRESHOLD) {
        ccn_mul(n, r, s, t);
    }
    else {
        cc_assert(r != s);
        cc_assert(r != t);
        cc_size m1=n/2;
        cc_size m0=n-m1; // m0>=m1 guaranteed. b=2^(m0*CCN_UNIT_BITS)
        cc_unit *tmp;
        // Karatsuba multiplication
        // s = s1.b + s0
        // t = t1.b + t0
        // s1,t1 of size m1=n/2 in size
        // s0,t0 of size m0=n-n/2 cc_units. m >=n/2

        tmp=CC_ALLOC_WS(ws,2*n);
        cc_assert(3*m0<=2*n);   // 2*n > 3*m
        cc_unit c0, c1;

        if (m0==m1) { // Size of the operands, not data dependent

            // |s1 - s0| in tmp[0]
            c0=ccn_abs_ws(ws, m0, &tmp[0],  &s[0],&s[m0]);

            // |t1 - t0| in tmp[m0]
            c1=ccn_abs_ws(ws, m0, &tmp[m0], &t[0],&t[m0]);
            ccn_zero(2*n-3*m0,&r[3*m0]); //clear upper part of r
        }
        else
        {
            // |s1 - s0| in tmp[0]
            ccn_setn(m0,&r[0],m1,&s[m0]); // s1
            c0=ccn_abs_ws(ws, m0, &tmp[0], &s[0],&r[0]);

            // |t1 - t0| in tmp[m0]
            ccn_setn(2*n,&r[0],m1,&t[m0]); // t1, clear upper part of r
            c1=ccn_abs_ws(ws, m0, &tmp[m0],&t[0],&r[0]);
        }
        c1=c0^c1;

        // r=b*(|s1 - s0| * |t1 - t0|)
        ccn_zero(m0,r);
        ccn_mul_ws(ws,m0,&r[m0],&tmp[0],&tmp[m0]);

        // r=(-1)^(c0+c1) * |s1 - s0| * |t1 - t0|
        ccn_zero(2*n-m0, &tmp[m0]);
        ccn_sub(2*n-m0, &tmp[m0], &tmp[m0], &r[m0]);
        ccn_mux(2*n-m0, c1, &r[m0], &r[m0], &tmp[m0]);
        ccn_zero(2*n-m0, &tmp[m0]);

        // x1.y1
        ccn_mul_ws(ws, m1,&tmp[0],&s[m0],&t[m0]);
        ccn_add(2*n-m0,&r[m0],&r[m0],&tmp[0]);        // r += b s1.t1
        ccn_add(2*m1,&r[2*m0],&r[2*m0],&tmp[0]);      // r += b^2 s1.t1

        // x0.y0
        ccn_mul_ws(ws, m0, &tmp[0],&s[0],&t[0]);
        ccn_add(2*n,&r[0],&r[0],&tmp[0]);           // r += s0.t0
        ccn_add(2*n-m0,&r[m0],&r[m0],&tmp[0]);      // r += b * s0.t0

        // Release workingspace.
    }
#if 0
    {
        // Debug
        cc_unit r_expected[2*n];
        ccn_mul(n, r_expected, s, t);
        if (ccn_cmp(2*n,r,r_expected)) {
            ccn_lprint(n,"Input s: ", s);
            ccn_lprint(n,"Input t: ", t);
            ccn_lprint(2*n,"Expected: ", r_expected);
            ccn_lprint(2*n,"Computed: ", r);
            cc_unit delta[2*n];
            ccn_sub(2*n,delta,r_expected,r);
            ccn_lprint(2*n,"Delta:    ", delta);
        }
        cc_assert(ccn_cmp(2*n,r,r_expected)==0);
    }
#endif // 0 debug
    CC_FREE_BP_WS(ws,bp);
}

#else // Schoolbook
/* Multiplication using a workspace. */
void ccn_mul_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    (void) ws;
    ccn_mul(n, r, s, t);
}
#endif

#if !CCN_MUL_ASM

#if CCN_MUL1_ASM && CCN_ADDMUL1_ASM

/* Constant time. NOTE: Seems like r and s may overlap, but r and t may not.
   Also if n is 0 this still writes one word to r. */
void ccn_mul(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    const cc_size sn = n;
    cc_size tn = n;
    assert(r != s);
    assert(r != t);

    r[sn] = ccn_mul1 (sn, r, s, t[0]);
    while (tn > 1)
    {
        r += 1;
        t += 1;
        tn -= 1;
        r[sn] = ccn_addmul1 (sn, r, s, t[0]);
    }
}

#else /* !(CCN_MUL1_ASM && CCN_ADDMUL1_ASM) */

/* Do r = s * t, r is 2 * count cc_units in size, s and t are count * cc_units in size. */
void ccn_mul(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_assert(r != s);
    cc_assert(r != t);
    ccn_zero(count * 2, r);

#if !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH && (CCN_UNIT_SIZE == 8)
    typedef uint32_t cc_mulw;
    typedef uint64_t cc_muld;
#define r ((cc_mulw *)r)
#define s ((const cc_mulw *)s)
#define t ((const cc_mulw *)t)
#define CCMULW_BITS  (32)
#define CCMULW_MASK ((cc_mulw)~0)
    count *= CCN_UNIT_SIZE / sizeof(cc_mulw);
#else
    typedef cc_unit cc_mulw;
    typedef cc_dunit cc_muld;
#define CCMULW_BITS  CCN_UNIT_BITS
#define CCMULW_MASK CCN_UNIT_MASK
#endif

    cc_muld prod1, prod2, carry1 = 0, carry2 = 0;
    const cc_mulw *aptr, *bptr = t;
    cc_mulw *destptr, mult1, mult2;
    cc_size ix;
	for (ix = 0; ix < count - 1; ix += 2) {
		mult1 = *(bptr++);
		mult2 = *(bptr++);

		cc_mulw prevmul = 0;
		carry1 = 0;
		carry2 = 0;
		aptr = s;
		destptr = &r[ix];
		cc_muld prevDigit = *destptr;

		for (cc_size j = 0; j < count; ++j) {
			cc_mulw curmul = *aptr++;
			prevDigit += carry1 + carry2;

			prod1 = (cc_muld)curmul * mult1;
			prod2 = (cc_muld)prevmul * mult2;

			carry1 = prod1 >> CCMULW_BITS;
			carry2 = prod2 >> CCMULW_BITS;

			prod1 &= CCMULW_MASK;
			prod2 &= CCMULW_MASK;

			cc_muld prodsum = prod1 + prod2 + prevDigit;
			carry1 += prodsum >> CCMULW_BITS;
			prevDigit = *(destptr+1);
			*(destptr++) = (cc_mulw)prodsum;
			prevmul = curmul;
		}

		prod1 = prevDigit + carry1;
		prod1 += (cc_muld)prevmul * mult2;
		prod1 += carry2;
		carry1 = prod1 >> CCMULW_BITS;
		*(destptr++) = (cc_mulw)prod1;
		*destptr = (cc_mulw)carry1;
	}

    if (ix < count) {
        mult1 = *bptr;
        carry1 = 0;
        aptr = s;
        destptr = &r[ix];
        for (cc_size j = 0; j < count; ++j) {
            //prod = *(aptr++) * mult + *destptr + carry;
            prod1 = (cc_muld)(*aptr++);
            prod1 *= mult1;
            prod1 += *destptr;
            prod1 += carry1;
            *(destptr++) = (cc_mulw)prod1;
            carry1 = prod1 >> CCMULW_BITS;
        }
        *destptr = (cc_mulw)carry1;
    }
}

#endif /* !(CCN_MUL1_ASM && CCN_ADDMUL1_ASM) */

#endif /* !CCN_MUL_ASM */
