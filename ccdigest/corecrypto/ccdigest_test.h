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

#ifndef _CORECRYPTO_CCDIGEST_TEST_H_
#define _CORECRYPTO_CCDIGEST_TEST_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccdigest.h>

/* test functions */
int ccdigest_test(const struct ccdigest_info *di, size_t len,
              const void *data, const void *digest);

int ccdigest_test_chunk(const struct ccdigest_info *di, size_t len,
                        const void *data, const void *digest, size_t chunk);

struct ccdigest_vector {
    size_t len;
    const void *message;
    const void *digest;
};

int ccdigest_test_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v);
int ccdigest_test_chunk_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v, size_t chunk);

#endif /* _CORECRYPTO_CCDIGEST_TEST_H_ */
