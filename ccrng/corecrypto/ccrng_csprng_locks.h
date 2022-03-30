/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#ifndef _CORECRYPTO_CCRNG_CSPRNG_LOCKS_H_
#define _CORECRYPTO_CCRNG_CSPRNG_LOCKS_H_

#include <corecrypto/cc_config.h>

struct ccrng_csprng_lock_ctx;
int ccrng_csprng_lock_init(struct ccrng_csprng_lock_ctx *lock_ctx);

#if defined(_WIN32)
#include <windows.h>
#endif

//==============================================================================
//
//          ccrng support for multithreaded environments
//
// This part of corecrypto is OS dependent and it serves two purposes
// a) It allows multiple threads to use ccrng()
// b) If the process is forked, it reseeds the ccrng, so that parent and child
//    state differs and generate different random numbers
//==============================================================================

#if CC_LINUX && CC_KERNEL && CC_DARWIN && CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
#define CCRNG_MULTITHREAD_POSIX 0 // this is only to allow linux development on macOS. It is not useful in practice.
#define CCRNG_MULTITHREAD_USER 0
#define CCRNG_MULTITHREAD_WIN 0
#define CCRNG_MULTITHREAD_KERNEL 1
#elif CC_DARWIN && !CC_KERNEL && !CC_USE_L4 && \
    !CC_EFI && CC_INTERNAL_SDK // For Apple OSs (macOS, iOS, watchOS, tvOS), except kernel, L4 and EFI
#define CCRNG_MULTITHREAD_POSIX 0
#define CCRNG_MULTITHREAD_USER 1
#define CCRNG_MULTITHREAD_WIN 0
#define CCRNG_MULTITHREAD_KERNEL 0
#elif CC_DARWIN && CC_KERNEL // For the Apple Kernel
#define CCRNG_MULTITHREAD_POSIX 0
#define CCRNG_MULTITHREAD_USER 0
#define CCRNG_MULTITHREAD_WIN 0
#define CCRNG_MULTITHREAD_KERNEL 1
#elif defined(_WIN32) // for Windows
#define CCRNG_MULTITHREAD_POSIX 0
#define CCRNG_MULTITHREAD_USER 0
#define CCRNG_MULTITHREAD_WIN 1
#define CCRNG_MULTITHREAD_KERNEL 0
#elif CC_LINUX || !CC_INTERNAL_SDK // for systems that support pthread, such as Linux
#define CCRNG_MULTITHREAD_POSIX 1
#define CCRNG_MULTITHREAD_USER 0
#define CCRNG_MULTITHREAD_WIN 0
#define CCRNG_MULTITHREAD_KERNEL 0
#else
#error No multithread environment defined for ccrng_cryptographic.
#endif

//------------------------------------------------------------------------------
// os/lock library, Apple userland
//------------------------------------------------------------------------------
#if CCRNG_MULTITHREAD_USER
#include <pthread.h>
#include <os/lock.h>

#ifndef __BLOCKS__
#warning no blocks support
#endif /* __BLOCKS__ */

#define CSPRNG_LOCK(rng) os_unfair_lock_lock(&(rng)->lock_ctx.lock)
#define CSPRNG_UNLOCK(rng) os_unfair_lock_unlock(&(rng)->lock_ctx.lock)
#define CSPRNG_ASSERT_LOCK(rng) os_unfair_lock_assert_owner(&(rng)->lock_ctx.lock)

struct ccrng_csprng_lock_ctx {
    os_unfair_lock lock;
};

//------------------------------------------------------------------------------
//          POSIX library, Linux
//------------------------------------------------------------------------------
#elif CCRNG_MULTITHREAD_POSIX
#include <pthread.h>

#define CSPRNG_LOCK(rng) pthread_mutex_lock(&((rng)->lock_ctx.mutex))
#define CSPRNG_UNLOCK(rng) pthread_mutex_unlock(&((rng)->lock_ctx.mutex))
#define CSPRNG_ASSERT_LOCK(rng)

struct ccrng_csprng_lock_ctx {
    pthread_mutex_t mutex;
};

//------------------------------------------------------------------------------
//          Kext, XNU
//------------------------------------------------------------------------------
#elif CCRNG_MULTITHREAD_KERNEL

#include <kern/locks.h>
#define CSPRNG_LOCK(rng) lck_mtx_lock((rng)->lock_ctx.mutex)
#define CSPRNG_UNLOCK(rng) lck_mtx_unlock((rng)->lock_ctx.mutex)
#define CSPRNG_ASSERT_LOCK(rng) lck_mtx_assert((rng)->lock_ctx.mutex, LCK_MTX_ASSERT_OWNED);

struct ccrng_csprng_lock_ctx {
    lck_mtx_t *mutex;
    lck_grp_t *group;
};

//------------------------------------------------------------------------------
//          Windows
//------------------------------------------------------------------------------
#elif CCRNG_MULTITHREAD_WIN

#define CSPRNG_LOCK(rng)                                                      \
    if (WaitForSingleObject((rng)->lock_ctx.hMutex, INFINITE) != WAIT_OBJECT_0) \
        return CCERR_INTERNAL;
#define CSPRNG_UNLOCK(rng) ReleaseMutex((rng)->lock_ctx.hMutex)
#define CSPRNG_ASSERT_LOCK(rng)

struct ccrng_csprng_lock_ctx {
    HANDLE hMutex;
};

//------------------------------------------------------------------------------
//          default
//------------------------------------------------------------------------------
#else
#error "CSPRNG_LOCK(), CSPRNG_UNLOCK(), and CSPRNG_ASSERT_LOCK() are not implemented."
#endif /* CCRNG_MULTITHREAD_USER */

#endif /* _CORECRYPTO_CCRNG_CSPRNG_LOCKS_H_ */
