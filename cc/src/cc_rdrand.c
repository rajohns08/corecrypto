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

#include <corecrypto/cc_runtime_config.h>
#include "cc_internal.h"

#if defined(__x86_64__)

bool cc_rdrand(uint64_t *rand)
{
    bool ok;

    if (CC_HAS_RDRAND()) {
        asm volatile ("rdrand %0; setc %1" : "=r"(rand), "=qm"(ok) : : "cc");
    } else {
        *rand = 0;
        ok = false;
    }

    return ok;
}

#else

bool cc_rdrand(uint64_t *rand)
{
    *rand = 0;
    return false;
}

#endif
