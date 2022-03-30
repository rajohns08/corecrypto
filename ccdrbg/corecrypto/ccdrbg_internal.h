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

#ifndef _CORECRYPTO_CCDRBG_INTERNAL_H_
#define _CORECRYPTO_CCDRBG_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg_impl.h>
#include <corecrypto/ccdrbg.h>

/*
 * NIST SP 800-90 TRNG DRBG
 *
 * Call into the SEP DRBG and perform a SP 800-90 test operation.
 */
void ccdrbg_factory_trng(struct ccdrbg_info *info);

/* Required length of the various TRNG entropy and personalization inputs. */
#define CCDRBG_TRNG_VECTOR_LEN     48

#endif /* _CORECRYPTO_CCDRBG_INTERNAL_H_ */
