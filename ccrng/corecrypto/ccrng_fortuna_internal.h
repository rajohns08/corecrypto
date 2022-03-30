/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_
#define _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng_fortuna.h>

#if CC_KERNEL

#include <kern/locks.h>
#define CCRNG_FORTUNA_LOCK_INIT(ctx) lck_mtx_alloc_init((ctx)->lock.group, LCK_ATTR_NULL)
#define CCRNG_FORTUNA_LOCK_LOCK(ctx) lck_mtx_lock((ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_TRYLOCK(ctx) lck_mtx_try_lock((ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_UNLOCK(ctx) lck_mtx_unlock((ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_ASSERT(ctx) lck_mtx_assert((ctx)->lock.mutex, LCK_MTX_ASSERT_OWNED);

#elif CC_ANDROID || CC_LINUX

#include <pthread.h>
#define CCRNG_FORTUNA_LOCK_INIT(ctx) ((const pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER)
#define CCRNG_FORTUNA_LOCK_LOCK(ctx) pthread_mutex_lock(&ctx->lock.mutex)
#define CCRNG_FORTUNA_LOCK_TRYLOCK(ctx) pthread_mutex_trylock(&ctx->lock.mutex)
#define CCRNG_FORTUNA_LOCK_UNLOCK(ctx) pthread_mutex_unlock(&ctx->lock.mutex)
#define CCRNG_FORTUNA_LOCK_ASSERT(ctx)

#else

#include <os/lock.h>
#define CCRNG_FORTUNA_LOCK_INIT(ctx) (OS_UNFAIR_LOCK_INIT)
#define CCRNG_FORTUNA_LOCK_LOCK(ctx) os_unfair_lock_lock(&(ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_TRYLOCK(ctx) os_unfair_lock_trylock(&(ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_UNLOCK(ctx) os_unfair_lock_unlock(&(ctx)->lock.mutex)
#define CCRNG_FORTUNA_LOCK_ASSERT(ctx) os_unfair_lock_assert_owner(&(ctx)->lock.mutex)

#endif

/*
 Internal Fortuna
 */

#define CCRNG_FORTUNA_LABEL(op) { 0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, op }

enum CCRNG_FORTUNA_OP {
    CCRNG_FORTUNA_OP_SCHEDRESEED = 2,
    CCRNG_FORTUNA_OP_ADDENTROPY = 3,
};

#endif /* _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_ */
