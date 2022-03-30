/* Copyright (c) (2011,2012,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZ_PRIV_H_
#define _CORECRYPTO_CCZ_PRIV_H_

#include <corecrypto/ccz.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>
#include <stdlib.h>  /* For abs() */

#ifndef CCZ_PREC
#define CCZ_PREC                 32     /* default units of precision */
#endif

/* Error codes. */
enum {
    CCZ_OK = 0,
    CCZ_MEM,
};

#define ccz_zp_decl(_ccz_, _name_) \
    cczp_decl_n(ccz_n(_ccz_), _name_); \
    CCZP_N(_name_) = ccz_n(_ccz_); \
    ccn_set(ccz_n(_ccz_), CCZP_PRIME(_name_), _ccz_->u);


CC_INLINE CC_NONNULL_ALL
int ccz_sign(const ccz *s) {
    return s->sac < 0 ? -1 : 1;
}

CC_INLINE CC_NONNULL((1))
void ccz_set_sign(ccz *r, int sign)
{
    if (ccz_sign(r) != sign)
        r->sac = -r->sac;
}

CC_INLINE CC_NONNULL_ALL
cc_size ccz_n(const ccz *s) {
    return s->n;
}

CC_INLINE CC_NONNULL((1))
void ccz_set_n(ccz *r, cc_size n) {
    r->n = n;
}

CC_INLINE CC_NONNULL_ALL
cc_size ccz_capacity(const ccz *s) {
    return (cc_size)abs(s->sac);
}

CC_INLINE CC_NONNULL((1))
void ccz_set_capacity(ccz *r, cc_size capacity)
{
    if (ccz_capacity(r) < capacity) {
        size_t ncapacity = capacity + (CCZ_PREC * 2) - (capacity % CCZ_PREC);
        cc_unit *t;
        if (ccz_capacity(r))
            t = r->isa->ccz_realloc(r->isa->ctx, ccn_sizeof_n(ccz_capacity(r)), r->u, ccn_sizeof_n(ncapacity));
        else
            t = r->isa->ccz_alloc(r->isa->ctx, ccn_sizeof_n(ncapacity));

        r->sac = r->sac < 0 ? -(int)ncapacity : (int)ncapacity;
        r->u = t;
    }
}

#endif /* _CORECRYPTO_CCZ_PRIV_H_ */
