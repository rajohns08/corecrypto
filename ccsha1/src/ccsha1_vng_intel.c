/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */



#include <corecrypto/ccsha1.h>
#include "ccsha1_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"

/* This is intel only */
#if CCSHA1_VNG_INTEL

#if defined(__x86_64__)
void ccsha1_vng_intel_compress_AVX2(ccdigest_state_t c, size_t num, const void *p) __asm__("_ccsha1_vng_intel_compress_AVX2");
void ccsha1_vng_intel_compress_AVX1(ccdigest_state_t c, size_t num, const void *p) __asm__("_ccsha1_vng_intel_compress_AVX1");
#endif
void ccsha1_vng_intel_compress_SupplementalSSE3(ccdigest_state_t c, size_t num, const void *p) __asm__("_ccsha1_vng_intel_compress_SupplementalSSE3");

#if CC_ACCELERATECRYPTO && defined(__x86_64__)
#include "AccelerateCrypto.h"

void AccelerateCrypto_SHA1(ccdigest_state_t c, size_t num, const void *p);

void AccelerateCrypto_SHA1(ccdigest_state_t c, size_t num, const void *p) 
{
    AccelerateCrypto_SHA1_compress((uint32_t*) c, num, p);
}

const struct ccdigest_info ccsha1_vng_intel_x86_64_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = AccelerateCrypto_SHA1,
    .final = ccdigest_final_64be,
};
#endif

#if defined(__x86_64__)
const struct ccdigest_info ccsha1_vng_intel_AVX2_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = ccsha1_vng_intel_compress_AVX2,
    .final = ccdigest_final_64be,
};

const struct ccdigest_info ccsha1_vng_intel_AVX1_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = ccsha1_vng_intel_compress_AVX1,
    .final = ccdigest_final_64be,
};
#endif

const struct ccdigest_info ccsha1_vng_intel_SupplementalSSE3_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = ccsha1_vng_intel_compress_SupplementalSSE3,
    .final = ccdigest_final_64be,
};

#endif /* CCSHA1_VNG_INTEL */

