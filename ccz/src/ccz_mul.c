/* Copyright (c) (2011,2012,2014,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccz_priv.h>

void ccz_mul(ccz *r, const ccz *_s, const ccz *_t)
{
    //s will the largest array of _s and _t
    int cond = ccz_n(_s) > ccz_n(_t);
    const ccz *s = cc_muxp(cond, _s, _t);
    const ccz *t = cc_muxp(cond, _t, _s);

    ccz_set_sign(r, ccz_sign(s) * ccz_sign(t));
#if 0
    ccz_set_capacity(r, ccz_n(s) + ccz_n(t));
    ccn_muln(ccz_n(s), r, s, ccz_n(t), t);
#else

    ccz_set_capacity(r, 2 * ccz_n(s));
    /* TODO Use r->u instead of stack allocation here if in place ccn_mul works. */
    cc_unit u[ccz_n(s)];
    cc_unit v[ccz_n(s)];
    ccn_setn(ccz_n(s), u, ccz_n(t), t->u); // represent t on ccz_n(s) units
    ccn_set(ccz_n(s), v, s->u);            // To support s->u == r->u, not in a if to avoid time leakage
    ccn_mul(ccz_n(s), r->u, v, u);
#endif
    ccz_set_n(r, ccn_n(ccz_n(s) + ccz_n(t), r->u));
}

