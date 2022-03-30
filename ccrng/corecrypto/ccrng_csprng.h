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

#ifndef _CORECRYPTO_CCRNG_CSPRNG_H_
#define _CORECRYPTO_CCRNG_CSPRNG_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng_csprng_locks.h>
#include <stddef.h>
#include <stdbool.h>

#define CCRNG_CSPRNG_ENTROPY_SIZE 64
#define CCRNG_CSPRNG_DRBG_STATE_MAX_SIZE ((size_t)1280)
#define CCRNG_CSPRNG_CACHED_BUF_SIZE ((size_t)256)
#define CCRNG_CSPRNG_CACHED_POS_END ((ptrdiff_t)CCRNG_CSPRNG_CACHED_BUF_SIZE)
#define CCRNG_CSPRNG_MAX_REQUEST_SIZE ((size_t)4096)
#define CCRNG_CSPRNG_MAX_RESEED_RETRY 100

struct ccrng_csprng_state;

typedef int (*ccrng_csprng_getentropy)(size_t *entropy_len, void *entropy, void *getentropy_ctx);

typedef bool (*ccrng_csprng_needreseed)(void *reseed_ctx);
typedef void (*ccrng_csprng_reseedcomplete)(void *reseed_ctx);

struct ccrng_csprng_state {
    CCRNG_STATE_COMMON
    CC_SPTR(ccrng_csprng_state, ccrng_csprng_getentropy getentropy);
    void *getentropy_ctx;
    CC_SPTR(ccrng_csprng_state, ccrng_csprng_needreseed needreseed);
    CC_SPTR(ccrng_csprng_state, ccrng_csprng_reseedcomplete reseedcomplete);
    void *reseed_ctx;
    
    struct ccdrbg_info drbg_info;
    uint8_t drbg_state[CCRNG_CSPRNG_DRBG_STATE_MAX_SIZE];
    struct {
        uint8_t buf[CCRNG_CSPRNG_CACHED_BUF_SIZE];
        ptrdiff_t pos;
    } random;
    struct ccrng_csprng_lock_ctx lock_ctx;
};

int ccrng_csprng_init(struct ccrng_csprng_state *rng,
                      size_t seed_len, const void *seed,
                      size_t nonce_len, const void *nonce,
                      size_t personalization_len, const void *personalization);

int ccrng_csprng_reseed(struct ccrng_csprng_state *rng,
                        size_t seed_len, const void *seed,
                        size_t nonce_len, const void *nonce);

// Force the implementation to reseed with getentropy calls
int ccrng_csprng_reseed_get_entropy(struct ccrng_csprng_state *rng,
                                    size_t nonce_len, const void *nonce);

#endif /* _CORECRYPTO_CCRNG_CSPRNG_H_ */
