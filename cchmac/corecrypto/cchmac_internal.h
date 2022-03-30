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

#ifndef _CORECRYPTO_CCHMAC_INTERNAL_H_
#define _CORECRYPTO_CCHMAC_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>

struct cchmac_test_input {
    const struct ccdigest_info *di;
    size_t key_len;
    const void *key;
    size_t data_len;
    const void *data;
    size_t mac_len;
    const void *expected_mac;
};

int cchmac_test(const struct cchmac_test_input *input);
int cchmac_test_chunks(const struct cchmac_test_input *input, size_t chunk_size);

#endif /* _CORECRYPTO_CCHMAC_INTERNAL_H_ */
