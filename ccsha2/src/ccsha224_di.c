/* Copyright (c) (2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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

#include "corecrypto/fipspost_trace.h"

const struct ccdigest_info *ccsha224_di(void)
{
    FIPSPOST_TRACE_EVENT;

#if  CCSHA2_VNG_INTEL
#if defined (__x86_64__)
    if (CC_HAS_AVX512_AND_IN_KERNEL())
        return &ccsha224_vng_intel_SupplementalSSE3_di;
    else
#if CC_ACCELERATECRYPTO
    return &ccsha224_vng_intel_di;  // use AccelerateCrypto
#else
    return ( (CC_HAS_AVX2() ? &ccsha224_vng_intel_AVX2_di :
            ( (CC_HAS_AVX1() ? &ccsha224_vng_intel_AVX1_di :
            &ccsha224_vng_intel_SupplementalSSE3_di ) ) ) ) ;
#endif
#else
    return &ccsha224_vng_intel_SupplementalSSE3_di;
#endif
#elif  CCSHA2_VNG_ARM
    return &ccsha224_vng_arm_di;
#else
    return &ccsha224_ltc_di;
#endif
}
