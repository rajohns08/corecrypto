/* Copyright (c) (2014-2016,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cccycles.h"
#include <stdio.h>
#include <sys/sysctl.h>

#if (CC_CYCLE_SELECT==CC_CYCLE_KPERF_FIX)
/* Use fix register, shared with power management */

// Return the current value of the timer.
uint64_t KPC_ReadTime(void)
{
    static uint32_t init=0;
    uint64_t counters[64];

    if (init==0)
    {
        kpc_set_counting(KPC_CLASS_FIXED_MASK);
        kpc_set_thread_counting(KPC_CLASS_FIXED_MASK);
        init=1;
    }

    kpc_get_thread_counters(0, 64, counters);
#if defined(__arm64__) || defined(__arm__)
    return counters[0];
#else
    return counters[1];
#endif
}

#elif (CC_CYCLE_SELECT==CC_CYCLE_KPERF_CONFIG)
/* Use configurable counter */

#if defined(__arm64__) || defined(__arm__)
#define CORE_CYCLE 0x2

static uint64_t config[] = {CORE_CYCLE, 0, 0, 0, 0, 0, 0, 0};

#else // Intel
#define IA32_EVENT_UNHALTED_CORE_UMASK     0x00
#define IA32_EVENT_UNHALTED_CORE_EVENT     0x3c
#define IA32_EVENT_INST_RET_UMASK     0x00
#define IA32_EVENT_INST_RET_EVENT     0xc0

#define IA32_EVTSEL_EVENT_MASK        (0xff)
#define IA32_EVTSEL_EVENT_SHIFT          (0)
#define IA32_EVTSEL_UMASK_MASK      (0xff00)
#define IA32_EVTSEL_UMASK_SHIFT          (8)
#define IA32_EVTSEL_USR_MASK       (0x10000)
#define IA32_EVTSEL_EN_MASK       (0x400000)

#define USER_CYCLES (IA32_EVENT_UNHALTED_CORE_EVENT << IA32_EVTSEL_EVENT_SHIFT) \
| (IA32_EVENT_UNHALTED_CORE_UMASK << IA32_EVTSEL_UMASK_SHIFT) \
| IA32_EVTSEL_USR_MASK \
| IA32_EVTSEL_EN_MASK
#define USER_INSTRS (IA32_EVENT_INST_RET_EVENT << IA32_EVTSEL_EVENT_SHIFT) \
| (IA32_EVENT_INST_RET_UMASK << IA32_EVTSEL_UMASK_SHIFT) \
| IA32_EVTSEL_USR_MASK \
| IA32_EVTSEL_EN_MASK

static uint64_t config[] = {USER_CYCLES, 0, 0, 0, 0, 0, 0, 0};
#endif // Arm or Intel

// Return the current value of the timer.
uint64_t KPC_ReadTime(int *error)
{
    static uint64_t counters[64];
    bool init=false;
    int r;

    if (!init)
    {
        // Disable kpc whitelist to work with clpc. Otherwise kpc cycle counter always reports 0.
#ifdef __arm64__
        int disable = 1;
        r = sysctlbyname("kpc.disable_whitelist", NULL, 0, &disable, sizeof(disable));
        if (r) {
            printf("Failed to set kpc.disable_whitelist\n" );
            *error=-1;
        }
#endif // __arm64__

        /* program configurable counters */
        r = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK,
                           config);
        if (r) {
            printf("Failed to set config - Test must run as Root\n" );
            *error=-1;
        }
        kpc_set_counting(KPC_CLASS_CONFIGURABLE_MASK);
        kpc_set_thread_counting( KPC_CLASS_CONFIGURABLE_MASK);
    }
    r = kpc_get_thread_counters(0, 64, counters);
    if (r)
    {
        printf("Failed to read cycle counter\n" );
        *error=-1;
    }
    return counters[0];
}

#endif // Time source


