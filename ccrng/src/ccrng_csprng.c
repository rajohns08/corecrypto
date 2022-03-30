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


#include <corecrypto/ccrng_csprng.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_absolute_time.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccdigest.h>

static int reseed_internal(struct ccrng_csprng_state *rng,
                           size_t seed_len, const void *seed,
                           size_t nonce_len, const void *nonce)
{
    CSPRNG_ASSERT_LOCK(rng);

    int drbg_status = ccdrbg_reseed(&rng->drbg_info, (struct ccdrbg_state *) &rng->drbg_state, seed_len, seed, nonce_len, nonce);

    if (drbg_status == CCERR_OK) {
        rng->random.pos = CCRNG_CSPRNG_CACHED_POS_END;
        rng->reseedcomplete(rng->reseed_ctx);
    }

    return drbg_status;
}


static int getentropy_and_reseed(struct ccrng_csprng_state *rng) {
    CSPRNG_ASSERT_LOCK(rng);

    int status = CCERR_OK;
    uint8_t entropy[CCRNG_CSPRNG_ENTROPY_SIZE];
    size_t entropy_len = sizeof(entropy);

    // In normal conditions, we will only perform one iteration of
    // this loop. We limit the number of retries to avoid looping
    // forever.
    for (size_t i = 0; i < CCRNG_CSPRNG_MAX_RESEED_RETRY; i++)
    {
        entropy_len = sizeof(entropy);
        status = rng->getentropy(&entropy_len, entropy, rng->getentropy_ctx);
        if (status != CCERR_OK) {
            continue;
        }

        status = reseed_internal(rng, sizeof(entropy), entropy, 0, NULL);
        if (status != CCERR_OK) {
            continue;
        }
        break; // We've succeeded
    }

    cc_clear(sizeof(entropy), entropy);
    return status;
}

static int ccrng_csprng_generate(struct ccrng_state *rng_in, size_t nbytes, void *bytes)
{
    struct ccrng_csprng_state *rng = (struct ccrng_csprng_state *)rng_in;
    // Although it is overloaded to be a general error flag, the
    // primary purpose of this variable is to track the status of the
    // underlying DRBG.
    int drbg_status = CCDRBG_STATUS_OK;
    uint8_t *out = (uint8_t *) bytes;

    while ((nbytes > 0) && ((drbg_status == CCDRBG_STATUS_OK) || (drbg_status == CCDRBG_STATUS_NEED_RESEED))) {
        CSPRNG_LOCK(rng);

        if (rng->needreseed(rng->reseed_ctx) || drbg_status == CCDRBG_STATUS_NEED_RESEED) {
            drbg_status = getentropy_and_reseed(rng);
        }

        if (drbg_status != CCDRBG_STATUS_OK) {
            cc_try_abort("Fatal error with prediction break, cannot reseed");
            CSPRNG_UNLOCK(rng);
            goto exit;
        }

        if (nbytes <= sizeof(rng->random.buf)) {
            uint8_t *p = rng->random.buf + rng->random.pos;
            uint8_t *end = rng->random.buf + CCRNG_CSPRNG_CACHED_POS_END;
            size_t left = (size_t)(end - p);
            size_t take = CC_MIN(nbytes, left);

            cc_memcpy(out, p, take);
            cc_clear(take, p);
            rng->random.pos += take;
            out += take;
            nbytes -= take;

            if (nbytes > 0) {
                drbg_status = ccdrbg_generate(&rng->drbg_info, (struct ccdrbg_state *) &rng->drbg_state, sizeof(rng->random.buf), rng->random.buf, 0, NULL);

                if (drbg_status == CCDRBG_STATUS_OK) {
                    cc_memcpy(out, rng->random.buf, nbytes);
                    cc_clear(nbytes, rng->random.buf);
                    rng->random.pos = (ptrdiff_t)nbytes;
                    nbytes = 0;
                }
            }
        } else {
            size_t req_size = CC_MIN(nbytes, CCRNG_CSPRNG_MAX_REQUEST_SIZE);
            drbg_status = ccdrbg_generate(&rng->drbg_info, (struct ccdrbg_state *) &rng->drbg_state, req_size, out, 0, NULL);

            if (drbg_status == CCDRBG_STATUS_OK) {
                // Move forward in output buffer only if the generation was successful
                // That can happen if last ccdrbg_generate requested reseeding for example
                out += req_size;
                nbytes -= req_size;
            }
        }

        CSPRNG_UNLOCK(rng);
    }

    if (nbytes > 0 || drbg_status != CCDRBG_STATUS_OK) {
        cc_try_abort("Unexpected error in ccrng_cryptographic generation");
    }
exit:
    return drbg_status;
}


int ccrng_csprng_init(struct ccrng_csprng_state *rng,
                      size_t seed_len, const void *seed,
                      size_t nonce_len, const void *nonce,
                      size_t personalization_len, const void *personalization)
{
    int err = CCERR_OK;

    rng->generate = ccrng_csprng_generate;
    rng->random.pos = CCRNG_CSPRNG_CACHED_POS_END;

    err = ccrng_csprng_lock_init(&rng->lock_ctx);
    cc_require(err == CCERR_OK, out);

    err = ccdrbg_init(&rng->drbg_info, (struct ccdrbg_state *) &rng->drbg_state, seed_len, seed, nonce_len, nonce, personalization_len, personalization);
    cc_require(err == CCERR_OK, out);
out:
    return err;
}

int ccrng_csprng_reseed(struct ccrng_csprng_state *rng,
                        size_t seed_len, const void *seed,
                        size_t nonce_len, const void *nonce)
{
    CSPRNG_LOCK(rng);

    int status = reseed_internal(rng, seed_len, seed, nonce_len, nonce);

    CSPRNG_UNLOCK(rng);
    return status;
}

// Force the implementation to reseed with getentropy calls
int ccrng_csprng_reseed_get_entropy(struct ccrng_csprng_state *rng,
                                    size_t nonce_len, const void *nonce)
{
    CSPRNG_LOCK(rng);

    uint8_t entropy[CCRNG_CSPRNG_ENTROPY_SIZE];
    size_t entropy_len = sizeof(entropy);

    int status = rng->getentropy(&entropy_len, entropy, rng->getentropy_ctx);
    if (status != CCERR_OK) {
        goto out;
    }

    status = reseed_internal(rng, entropy_len, entropy, nonce_len, nonce);

 out:
    CSPRNG_UNLOCK(rng);
    return status;
}
