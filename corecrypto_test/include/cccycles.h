/* Copyright (c) (2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_cccycles_h
#define corecrypto_cccycles_h

#include "cctime.h"

#define CC_CYCLE_KPERF_FIX    1
#define CC_CYCLE_KPERF_CONFIG 2
#define CC_CYCLE_TIME         3

/* Select source of cycle (or whatever is the closest to cycles) */
#ifndef CC_CYCLE_SELECT
#if TARGET_OS_OSX && (defined(TARGET_OS_SIMULATOR) && !TARGET_OS_SIMULATOR)
// Use KPERF
#define CC_CYCLE_SELECT  CC_CYCLE_KPERF_CONFIG
#else
#define CC_CYCLE_SELECT  CC_CYCLE_TIME
#endif
#endif

/* Portability */
#if defined(__has_include)     /* portability */
#if !__has_include(<kperf/kpc.h>) && (CC_CYCLE_SELECT == CC_CYCLE_KPERF_CONFIG)
#undef CC_CYCLE_SELECT
#define CC_CYCLE_SELECT  CC_CYCLE_TIME
#warning "CC_CYCLE KPERF not available, not an internal SDK?"
#endif
#endif


#if (CC_CYCLE_SELECT==CC_CYCLE_KPERF_FIX) || \
(CC_CYCLE_SELECT==CC_CYCLE_KPERF_CONFIG)
/* KPC is the most precise since it provides cycle count directly and therefore less influenced by performance management.
 However it requires to have the process run as root on iOS (for security reasons):

 CC_KPC_TIME_FIX uses the fixed counters, those may be shared with other processes so that
 this is not recommended
 CC_KPC_TIME_CONFIG configures one of the time for the need of the test. RECOMMENDED */

#include <kperf/kpc.h>
uint64_t KPC_ReadTime(int *error);

#define perf_cycle_start(errOut)    int  _perf_error=0; \
                                    uint64_t _perf_cycle_start = KPC_ReadTime(&_perf_error); \
                                    if (_perf_error) goto errOut

#define perf_cycle(errOut) (KPC_ReadTime(&_perf_error)- _perf_cycle_start); \
                           if (_perf_error) goto errOut

#else

// When KPC is not available, fallback on using time.
#define perf_cycle_start(errOut)    int  _perf_error=0; \
                                    perf_start()  \
                                    if (_perf_error) goto errOut



#define perf_cycle(errOut)          perf_time_raw();\
                                    if (_perf_error) goto errOut

#endif // Time source

#endif
