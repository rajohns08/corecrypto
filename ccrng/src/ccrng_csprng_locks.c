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

#include <corecrypto/ccrng_csprng_locks.h>
#include <corecrypto/cc.h>

#if CCRNG_MULTITHREAD_POSIX

int ccrng_csprng_lock_init(struct ccrng_csprng_lock_ctx *lock_ctx) {
    int rc = CCERR_INTERNAL;

    rc = pthread_mutex_init(&lock_ctx->mutex, NULL);
    return rc;
}

#elif CCRNG_MULTITHREAD_USER

int ccrng_csprng_lock_init(struct ccrng_csprng_lock_ctx *lock_ctx) {
    lock_ctx->lock = OS_UNFAIR_LOCK_INIT;
    return CCERR_OK;
}

#elif CCRNG_MULTITHREAD_WIN

int ccrng_csprng_lock_init(struct ccrng_csprng_lock_ctx *lock_ctx) {
    lock_ctx->hMutex = CreateMutex(NULL,  // default security attributes
                              FALSE, // initially not owned
                              NULL); // unnamed mutex
    
    if (lock_ctx->hMutex != NULL) {
        return CCERR_OK;
    }
    return CCERR_INTERNAL;
}

#elif CCRNG_MULTITHREAD_KERNEL

int ccrng_csprng_lock_init(struct ccrng_csprng_lock_ctx *lock_ctx) {
    /* allocate lock group attribute and group */
    lck_grp_attr_t *rng_slock_grp_attr;
    lck_attr_t *rng_slock_attr;

    rng_slock_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(rng_slock_grp_attr);
    lock_ctx->group = lck_grp_alloc_init("corecrypto_rng_lock", rng_slock_grp_attr);

    rng_slock_attr = lck_attr_alloc_init();
#if CORECRYPTO_DEBUG
    lck_attr_setdebug(rng_slock_attr); // set the debug flag
#endif
    lock_ctx->mutex = lck_mtx_alloc_init(lock_ctx->group, rng_slock_attr);

    lck_attr_free(rng_slock_attr);
    lck_grp_attr_free(rng_slock_grp_attr);

    return CCERR_OK;
}

#else
#error "ccrng_csprng_lock_init is not implemented."
#endif /* CCRNG_MULTITHREAD_USER */
