/* Copyright (c) (2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha2.h>
#include "ccsha2_internal.h"
#include <corecrypto/cc_runtime_config.h>

const struct ccdigest_info *ccsha384_di(void)
{
#if CC_USE_ASM && CCSHA2_VNG_INTEL
#if defined (__x86_64__)
    if (CC_HAS_AVX512_AND_IN_KERNEL())
        return (CC_HAS_SupplementalSSE3() ? &ccsha384_vng_intel_SupplementalSSE3_di : &ccsha384_ltc_di);
    else
#if CC_ACCELERATECRYPTO
    return &ccsha384_vng_intel_di;
#else
    return ( (CC_HAS_AVX2() ? &ccsha384_vng_intel_AVX2_di :
            ( (CC_HAS_AVX1() ? &ccsha384_vng_intel_AVX1_di :
            (CC_HAS_SupplementalSSE3() ? &ccsha384_vng_intel_SupplementalSSE3_di :
            &ccsha384_ltc_di) ) ) ) ) ;
#endif
#else
    return &ccsha384_ltc_di;
#endif
#elif CC_USE_ASM && CCSHA2_VNG_ARM
    return &ccsha384_vng_arm_di;
#else
    return &ccsha384_ltc_di;
#endif


}
