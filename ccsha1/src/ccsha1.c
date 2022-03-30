/* Copyright (c) (2010,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_runtime_config.h>

#include "corecrypto/fipspost_trace.h"

const struct ccdigest_info *ccsha1_di(void)
{
    FIPSPOST_TRACE_EVENT;

#if  CCSHA1_VNG_INTEL
#if defined (__x86_64__)
    if (CC_HAS_AVX512_AND_IN_KERNEL()) 
        return &ccsha1_vng_intel_SupplementalSSE3_di;
    else 
#if CC_ACCELERATECRYPTO
    return &ccsha1_vng_intel_x86_64_di;
#else   // not using acceleratecrypto
    return ( (CC_HAS_AVX2() ? &ccsha1_vng_intel_AVX2_di :
            ( (CC_HAS_AVX1() ? &ccsha1_vng_intel_AVX1_di :
            &ccsha1_vng_intel_SupplementalSSE3_di ) ) ) ) ;
#endif  // CC_ACCELERATECRYPTO
#else    
    return &ccsha1_vng_intel_SupplementalSSE3_di;
#endif
#elif  CCSHA1_VNG_ARM
    return &ccsha1_vng_arm_di;
#else
    return &ccsha1_ltc_di;
#endif
}
