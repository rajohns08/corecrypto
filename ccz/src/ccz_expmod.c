/* Copyright (c) (2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cczp.h>
#include "cczp_internal.h"
#include "cc_macros.h"

int ccz_expmod(ccz *r, const ccz *s, const ccz *t, const ccz *u) {
    int status=-1;
    assert(r != s); // actually I think this *is* allowed.
    assert(r != t); // actually I think this *is* allowed.

    ccz_set_capacity(r, ccz_n(u));
    cczp_decl_n(ccz_n(u), zu);
    CCZP_N(zu) = ccz_n(u);
    ccn_set(ccz_n(u), CCZP_PRIME(zu), u->u);
    status=cczp_init(zu);
    cc_require(status==0,errOut);

    ccz tmp;
    const ccz *m;
    ccz_init(s->isa, &tmp);

    if (ccz_cmp(s, u) >= 0) {
        ccz_mod(&tmp, s, u);
        ccz_set_capacity(&tmp, ccz_n(u));
        ccn_zero(ccz_capacity(&tmp)-ccz_n(u), tmp.u + ccz_n(u));
        m = &tmp;
	} else if(ccz_n(s) < ccz_n(u)) {
        ccz_set(&tmp, s);
        ccz_set_capacity(&tmp, ccz_n(u));
        ccn_zero(ccz_capacity(&tmp)-ccz_n(s), tmp.u + ccz_n(s));
        m = &tmp;
    } else {
        m = s;
    }

    size_t tbits = ccz_bitlen(t);
    ccz_set_capacity(&tmp, ccz_n(m));
    cczp_modn(zu,tmp.u,m->n,m->u);
    /* Ignoring cczp_powern error code; arguments guaranteed to be valid. */
    status=cczp_powern(zu, r->u, tmp.u, tbits, t->u);
    ccz_set_n(r, ccn_n(cczp_n(zu), r->u));
    ccz_free(&tmp);
errOut:
    return status;
}
