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

#include <stdatomic.h>

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>

#include "cc_memory.h"
#include "cckprng_internal.h"

static int csprng_getentropy(size_t *entropy_nbytes, void *entropy, void *getentropy_ctx)
{
    int err = ccrng_fortuna_generate(getentropy_ctx, *entropy_nbytes, entropy);
    if (err < 0) {
        *entropy_nbytes = 0;
    }

    return err;
}

static bool csprng_needreseed(void *reseed_ctx)
{
    struct cckprng_ctx *ctx = reseed_ctx;
    return atomic_exchange_explicit(&ctx->needreseed, false, memory_order_relaxed);
}

static void csprng_reseedcomplete(CC_UNUSED void *reseed_ctx)
{

}

void cckprng_init(struct cckprng_ctx *ctx,
                  size_t seed_nbytes,
                  const void *seed,
                  size_t nonce_nbytes,
                  const void *nonce,
                  cckprng_getentropy getentropy,
                  void *getentropy_arg)
{
    cc_clear(sizeof(*ctx), ctx);

    ccrng_fortuna_init(&ctx->fortuna_ctx, getentropy, getentropy_arg);

    struct ccrng_csprng_state *rng = &ctx->csprng_ctx;
    rng->getentropy = csprng_getentropy;
    rng->getentropy_ctx = &ctx->fortuna_ctx;
    rng->needreseed = csprng_needreseed;
    rng->reseedcomplete = csprng_reseedcomplete;
    rng->reseed_ctx = ctx;

    struct ccdrbg_nistctr_custom drbg_custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 32,
        .strictFIPS = 1,
        .use_df = 1,
    };
    ccdrbg_factory_nistctr(&rng->drbg_info, &drbg_custom);

    const uint8_t ps[] = CCKPRNG_LABEL(CCKPRNG_OP_INIT_CSPRNG);
    int err = ccrng_csprng_init(rng, seed_nbytes, seed, nonce_nbytes, nonce, sizeof(ps), ps);
    if (err != CCERR_OK) {
        cc_abort("Failure to instantiate csprng_kernel");
    }
}

void cckprng_init_with_getentropy(struct cckprng_ctx *ctx,
                                  CC_UNUSED unsigned max_ngens,
                                  size_t seed_nbytes,
                                  const void *seed,
                                  size_t nonce_nbytes,
                                  const void *nonce,
                                  cckprng_getentropy getentropy,
                                  void *getentropy_arg)

{
    cckprng_init(ctx, seed_nbytes, seed, nonce_nbytes, nonce, getentropy, getentropy_arg);
}
