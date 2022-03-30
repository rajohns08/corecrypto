/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRC4_INTERNAL_H_
#define _CORECRYPTO_CCRC4_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrc4.h>

struct ccrc4_vector {
    size_t keylen;
    const void *key;
    size_t datalen;
    const void *pt;
    const void *ct;
};

int ccrc4_test(const struct ccrc4_info *rc4, const struct ccrc4_vector *v);

#endif /* _CORECRYPTO_CCRC4_INTERNAL_H_ */
