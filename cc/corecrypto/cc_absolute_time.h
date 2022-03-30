/* Copyright (c) (2016-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef cc_absolute_time_h
#define cc_absolute_time_h

#include <corecrypto/cc_config.h>
#include <stdint.h>

// For more info on mach_absolute_time() precision:
//     https://developer.apple.com/library/mac/qa/qa1398/_index.html

#if CC_USE_L4
    #include <ert/time.h>
    #define cc_absolute_time() ert_time_now()

    // L4 doesn't use a scaling factor
    #define cc_absolute_time_sf() (1.0 / 1000000000.0)
#elif CC_KERNEL
    #include <mach/mach_time.h>
    #include <kern/clock.h>
    #define cc_absolute_time() (mach_absolute_time())

     // Scale factor to convert absolute time to seconds
    #define cc_absolute_time_sf() ({                                        \
        struct mach_timebase_info info;                                     \
        clock_timebase_info(&info);                                         \
        ((double)info.numer) / (1000000000.0 * info.denom);                 \
    })
#elif CC_DARWIN
    #include <mach/mach_time.h>
    #define cc_absolute_time() (mach_absolute_time())

     // Scale factor to convert absolute time to seconds
    #define cc_absolute_time_sf() ({                                        \
        struct mach_timebase_info info;                                     \
        mach_timebase_info(&info);                                          \
        ((double)info.numer) / (1000000000.0 * info.denom);                 \
    })
#elif defined(_WIN32)
    #include <windows.h>
    CC_INLINE uint64_t cc_absolute_time(void) {
        LARGE_INTEGER time;
        QueryPerformanceCounter(&time); //resolution < 1us
        return (uint64_t)time.QuadPart;
     }

     CC_INLINE double cc_absolute_time_sf(){
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq); //performance counter freq in Hz
        return (double)1 / freq.QuadPart;
     }

#elif CC_LINUX
    #if CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
        #include <mach/mach_time.h>
        #define cc_absolute_time() (mach_absolute_time()) // To test compilation on mac
    #else
        // The following is specific to non x86 (arm/mips/etc...) architectures on Linux.
        #warning cc_absolute_time() has not been tested
        #include <time.h>
        #define NSEC_PER_USEC 1000ull
        CC_INLINE uint64_t cc_absolute_time() {
           struct timespec tm;
           clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
           return tm.tv_sec * 1000000000ull + tm.tv_nsec;
        }
    #endif // CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
    #define cc_absolute_time_sf() (1.0 / 1000000000.0)

#else
    #warning Target OS is not defined. There should be a definition for cc_absolute_time() for the target OS/platform.
#endif

#endif /* cc_absolute_time_h */
