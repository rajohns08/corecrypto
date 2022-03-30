/* Copyright (c) (2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef crypto_test_dh_h
#define crypto_test_dh_h

/* test API */

#include <stdio.h>
#include <stdbool.h>
#include "crypto_test_gp_lookup.h"

struct ccdh_compute_vector {
    size_t len;
    size_t pLen;
    const void *p;
    size_t qLen;
    const void *q;
    size_t gLen;
    const void *g;
    size_t xaLen;
    const void *xa;
    size_t yaLen;
    const void *ya;
    size_t xbLen;
    const void *xb;
    size_t ybLen;
    const void *yb;
    size_t zLen;
    const void *z;
    bool valid;
};

int ccdh_test_compute_vector(const struct ccdh_compute_vector *v);
void ccdh_gp_ramp_exponent_test(void);
void ccdh_copy_gp_test(void);

#endif /* crypto_test_dh_h */
