/* Copyright (c) (2012,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_H_
#define _CORECRYPTO_FIPSPOST_H_

#include <stdint.h>
#include <corecrypto/cc_config.h>

// Boot-Arg fips_mode Flags
//
// FIPS_MODE_FLAG_FULL is the default value when no other value is set, which
// is the case for all production devices.
//
// When performing tests, if _FORCEFAIL is set to true, then the tests
// intentionally fail and log their failure. The kernelspace and userspace
// flags can be enabled independently.
//
// If it's not desired to panic, supply the _NOPANIC flag with the
// _FORCEFAIL flag.
//
// Additional logging can be enabled by supplying the _VERBOSE flag.
//
// _NOINTEG is used to ignore just the results of the module integrity
// check process, which is very useful when setting breakpoints in the
// kext for diagnostic or auditing purposes.
//
// Supplying _TRACE causes a trace buffer to be accumulated of the instrumented
// functions for only one execution of the POST.  As the POST finishes, the
// _TRACE flag is cleared from the fips_mode and no further tracing will occur.
#define FIPS_MODE_FLAG_DEBUG        (1 << 0)
#define FIPS_MODE_FLAG_FULL         (1 << 1)
#define FIPS_MODE_FLAG_DISABLE      (1 << 2)
#define FIPS_MODE_FLAG_VERBOSE      (1 << 3)
#define FIPS_MODE_FLAG_US_FORCEFAIL (1 << 4)
#define FIPS_MODE_FLAG_KS_FORCEFAIL (1 << 5)
#define FIPS_MODE_FLAG_NOINTEG      (1 << 6)
#define FIPS_MODE_FLAG_TRACE        (1 << 7)
#define FIPS_MODE_FLAG_NOPANIC      (1 << 8)

#define FIPS_MODE_IS_DEBUG(MODE)        ((MODE) & FIPS_MODE_FLAG_DEBUG)
#define FIPS_MODE_IS_FULL(MODE)         ((MODE) & FIPS_MODE_FLAG_FULL)
#define FIPS_MODE_IS_DISABLE(MODE)      ((MODE) & FIPS_MODE_FLAG_DISABLE)
#define FIPS_MODE_IS_VERBOSE(MODE)      ((MODE) & FIPS_MODE_FLAG_VERBOSE)
#define FIPS_MODE_IS_US_FORCEFAIL(MODE) ((MODE) & FIPS_MODE_FLAG_US_FORCEFAIL)
#define FIPS_MODE_IS_KS_FORCEFAIL(MODE) ((MODE) & FIPS_MODE_FLAG_KS_FORCEFAIL)
#define FIPS_MODE_IS_NOINTEG(MODE)      ((MODE) & FIPS_MODE_FLAG_NOINTEG)
#define FIPS_MODE_IS_TRACE(MODE)        ((MODE) & FIPS_MODE_FLAG_TRACE)
#define FIPS_MODE_IS_NOPANIC(MODE)      ((MODE) & FIPS_MODE_FLAG_NOPANIC)

#if CC_KERNEL
#define FIPS_MODE_FLAG_FORCEFAIL        FIPS_MODE_FLAG_KS_FORCEFAIL
#define FIPS_MODE_IS_FORCEFAIL(MODE)    FIPS_MODE_IS_KS_FORCEFAIL(MODE)
#else
#define FIPS_MODE_FLAG_FORCEFAIL        FIPS_MODE_FLAG_US_FORCEFAIL
#define FIPS_MODE_IS_FORCEFAIL(MODE)    FIPS_MODE_IS_US_FORCEFAIL(MODE)
#endif

struct mach_header;

/*
 * Entrypoint for all POST tests.
 */
int fipspost_post(uint32_t fips_mode, struct mach_header *pmach_header);

#endif /* _CORECRYPTO_FIPSPOST_H_ */
