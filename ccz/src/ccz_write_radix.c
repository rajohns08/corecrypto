/* Copyright (c) (2012,2013,2014,2015,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

const char *ccn_radix_digit_map = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* q*t + r == s [e.g. s/t, q=quotient, r=remainder]. */
static void ccn_divn(cc_size nqs, cc_unit *q, cc_unit *r, const cc_unit *s, size_t nrt, cc_unit *t) {
    if (ccn_is_zero(nrt, t)) {
        /* Division by zero is illegal. */
        return;
    }

    /* If s < t then q = 0, r = s */
    if (ccn_cmpn(nqs, s, nrt, t) < 0) {
        if (r) ccn_setn(nrt, r, CC_MIN(nrt, nqs), s);
        if (q) ccn_zero(nqs, q);
        return;
    }

    /* s >= t => k >= 0 */
    size_t k = ccn_bitlen(nqs, s);
    size_t l = ccn_bitlen(nrt, t);
    assert(k >= l);
    k -= l;

    cc_unit tr[nqs];
    cc_unit tt[nqs];
    cc_unit tq[nqs];

    ccn_set(nqs, tr, s);

    ccn_setn(nqs, tt, nrt, t);
    ccn_shift_left_multi(nqs, tt, tt, k);

    ccn_zero(nqs, tq);

    for (;;) {
        if (ccn_cmp(nqs, tr, tt) >= 0) {
            ccn_sub(nqs, tr, tr, tt);
            ccn_set_bit(tq, k, 1);
        }
        if (!k)
            break;

        --k;
        ccn_shift_right(nqs, tt, tt, 1);
    }

    if (r) {
        ccn_setn(nrt, r, CC_MIN(nrt, nqs), tr);
    }
    if (q) {
        ccn_set(nqs, q, tq);
    }
}

static void ccn_div1(cc_size n, cc_unit *q, cc_unit *r, const cc_unit *s, cc_unit v) {
    if (n == 0) {
        *r = 0;
        return;
    }

    size_t k = ccn_bitlen(1, &v) - 1;
    size_t l = ccn_trailing_zeros(1, &v);
    if (k == l) {
        /* Divide by power of 2, remainder in *r. */
        *r = s[0] & (v - 1);
        ccn_shift_right(n, q, s, k);
    } else {
        ccn_divn(n, q, r, s, 1, &v);
    }
}

static size_t ccn_write_radix_size(cc_size n, const cc_unit *s,
                                   unsigned radix) {
    if (ccn_is_zero(n, s)) {
        return 1;
    }

    /* digs is the digit count */
    cc_unit uradix[1] = { radix };
    size_t k = ccn_bitlen(1, uradix) - 1;
    size_t l = ccn_trailing_zeros(1, uradix);
    if (k == l) {
        /* Radix is 2**k. */
        return (ccn_bitlen(n, s) + k - 1) / k;
    } else {
        size_t size = 0;
        n = ccn_n(n, s);
        cc_unit t[n];
        ccn_set(n, t, s);
        cc_unit v[1];
        while (n) {
            ccn_div1(n, t, v, t, radix);
            n = ccn_n(n, t);
            ++size;
        }
        return size;
    }
}

static void ccn_write_radix(cc_size n, const cc_unit *s,
                            size_t out_size, char *out, unsigned radix) {
    assert(radix <= strlen(ccn_radix_digit_map));
    cc_unit t[n];
    cc_unit v[1]={0};
    ccn_set(n, t, s);
    /* Write from the end of the buffer backwards. */
    for (char *p = out, *q = p + out_size; p < q;) {
        ccn_div1(n, t, v, t, radix);
        n = ccn_n(n, t);
        *--q = ccn_radix_digit_map[v[0]];
        if (ccn_is_zero(n, t)) {
            /* Pad remaining space with zeros. */
            while (p < q) {
                *--q = '0';
            }
            break;
        }
    }
}

size_t ccz_write_radix_size(const ccz *s, unsigned radix) {
    return ccn_write_radix_size(ccz_n(s), s->u, radix) + (ccz_sign(s) < 0 ? 1 : 0);
}

void ccz_write_radix(const ccz *s, size_t out_size, void *out, unsigned radix) {
    char *p = out;
    if (ccz_sign(s) < 0) {
        *p++ = '-';
        --out_size;
    }
    ccn_write_radix(ccz_n(s), s->u, out_size, p, radix);
}
