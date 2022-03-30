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

#ifndef _CORECRYPTO_CCKPRNG_INTERNAL_H_
#define _CORECRYPTO_CCKPRNG_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/cckprng.h>
#include <corecrypto/ccrng_csprng.h>

#if CC_KERNEL

#include <kern/locks.h>
#define CCKPRNG_LOCK_INIT(ctx) lck_mtx_alloc_init((ctx)->lock.group, LCK_ATTR_NULL)
#define CCKPRNG_LOCK_LOCK(ctx) lck_mtx_lock((ctx)->lock.mutex)
#define CCKPRNG_LOCK_TRYLOCK(ctx) lck_mtx_try_lock((ctx)->lock.mutex)
#define CCKPRNG_LOCK_UNLOCK(ctx) lck_mtx_unlock((ctx)->lock.mutex)
#define CCKPRNG_LOCK_ASSERT(ctx) lck_mtx_assert((ctx)->lock.mutex, LCK_MTX_ASSERT_OWNED);

#elif CC_ANDROID || CC_LINUX

#include <pthread.h>
#define CCKPRNG_LOCK_INIT(ctx) ((const pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER)
#define CCKPRNG_LOCK_LOCK(ctx) pthread_mutex_lock(&ctx->lock.mutex)
#define CCKPRNG_LOCK_TRYLOCK(ctx) pthread_mutex_trylock(&ctx->lock.mutex)
#define CCKPRNG_LOCK_UNLOCK(ctx) pthread_mutex_unlock(&ctx->lock.mutex)
#define CCKPRNG_LOCK_ASSERT(ctx)

#else

#include <os/lock.h>
#define CCKPRNG_LOCK_INIT(ctx) (OS_UNFAIR_LOCK_INIT)
#define CCKPRNG_LOCK_LOCK(ctx) os_unfair_lock_lock(&(ctx)->lock.mutex)
#define CCKPRNG_LOCK_TRYLOCK(ctx) os_unfair_lock_trylock(&(ctx)->lock.mutex)
#define CCKPRNG_LOCK_UNLOCK(ctx) os_unfair_lock_unlock(&(ctx)->lock.mutex)
#define CCKPRNG_LOCK_ASSERT(ctx) os_unfair_lock_assert_owner(&(ctx)->lock.mutex)

#endif

/*
 Structures and functions for the CSPRNG that sits in front of Fortuna.
 */

extern struct ccrng_csprng_state g_csprng_kernel;
extern struct ccrng_csprng_fortuna_sched g_csprng_kernel_sched;
extern struct ccdrbg_nistctr_custom g_csprng_kernel_drbg_custom;

int ccrng_csprng_kernel_getentropy(struct ccrng_csprng_state *rng, size_t *entropy_len, void *entropy, void *getentropy_ctx);

/*
 Internal Fortuna
 */

void cckprng_rekeygens(struct cckprng_ctx *ctx);

#define CCKPRNG_LABEL(op) { 0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, op }

enum CCKPRNG_OP {
    CCKPRNG_OP_INIT = 0,
    CCKPRNG_OP_USERRESEED = 1,
    CCKPRNG_OP_SCHEDRESEED = 2,
    CCKPRNG_OP_ADDENTROPY = 3,
    CCKPRNG_OP_INIT_CSPRNG = 4,
};

#define CCKPRNG_REFRESH_MIN_NSAMPLES 32

#define CCKPRNG_SEEDSIZE 32
#define CCKPRNG_SEEDFILE "/var/db/prng.seed"
#define CCKPRNG_RANDOMDEV "/dev/random"

// Read the full seed file and provide its contents to the kernel PRNG
// via the random device.
int cckprng_loadseed(void);

// Request a seed from the kernel PRNG (via getentropy(2)) and persist
// it to the seed file for future boots. Ensure the seed file is
// readable and writable only by root.
int cckprng_storeseed(void);

#endif /* _CORECRYPTO_CCKPRNG_INTERNAL_H_ */
