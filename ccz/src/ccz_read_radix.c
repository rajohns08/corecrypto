/* Copyright (c) (2012,2015,2017,2018,2019) Apple Inc. All rights reserved.
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

#include <ctype.h>  /* For toupper(). */

extern const char *ccn_radix_digit_map;

static int ccn_digit_for_radix(cc_unit *r, char ch, unsigned radix) {
    *r=0; // Default value in case of error
    ch = ((radix < 36) ? (char)toupper((int)ch) : ch);
    for (size_t i = 0; i < radix; ++i) {
        if (ch == ccn_radix_digit_map[i]) {
            *r=i;
            return 0;
        }
    }
    // Not found
    return CCZ_INVALID_INPUT_ERROR;
}

static size_t ccn_read_radix_size(size_t data_size, unsigned radix) {
    cc_unit rad = radix - 1;
    return ccn_nof(ccn_bitlen(1, &rad) * data_size);
}

static int ccn_read_radix(cc_size n, cc_unit *r, size_t data_size,
                    const char *data, unsigned radix) {
    ccn_zero(n, r);
    cc_unit v;
    int rv=0;
    /* TODO: Performance win start n = 0 and increment in the loop as needed. */
    for (const char *end = data + data_size; data != end; ++data) {
        ccn_mul1(n, r, r, radix);
        rv |= ccn_digit_for_radix(&v, *data, radix); // v is zero in case of error
        ccn_add1(n, r, r, v);
    }
    return rv;
}

int ccz_read_radix(ccz *r, size_t data_size, const char *data, unsigned radix) {
    int rv;
    int sign=1;

    if ((radix==0) || (radix>strlen(ccn_radix_digit_map))) {
        return CCZ_INVALID_RADIX_ERROR; // Radix not supported
    }

    // Sign
    if (data_size) {
        if (*data == '-') {
            ++data;
            --data_size;
            sign=-1;
        }
        if (*data == '+') {
            ++data;
            --data_size;
            sign=1;
        }
    }

    // Absolute value
    cc_size n = ccn_read_radix_size(data_size, radix);
    ccz_set_capacity(r, n);
    rv=ccn_read_radix(n, r->u, data_size, data, radix);
    ccz_set_n(r, ccn_n(n, r->u));
    ccz_set_sign(r, sign);
    return rv;
}
