/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_POST_RSA_H_
#define _CORECRYPTO_FIPSPOST_POST_RSA_H_

#include <stdint.h>
#include <stdlib.h>

// DER RSA key used for RSA operation tests pulled from FIPS 186-2 RSA test vectors.
extern const uint8_t fipspost_post_rsa_test_key[];
extern const size_t fipspost_post_rsa_test_key_nbytes;

#endif
